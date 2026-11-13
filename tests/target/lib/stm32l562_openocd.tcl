# stm32l562_openocd.tcl
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# The STM32L562E-DK operations lib/stm32l562_probe.sh runs through OpenOCD,
# loaded after target/stm32l5x.cfg. With TZEN=1 the debugger is Secure; each
# operation prints one L5* line the shell parses, or L5ERR.

set l5_cpu stm32l5x.cpu
set l5_ran 0
set l5_saved {}

# Halt a running core for the duration of one operation. OpenOCD tags the
# debugger's accesses Non-secure (CSW HNONSEC) while the core sits in
# Non-secure state; every access here is a Secure one.
proc l5_hold {} {
    global l5_cpu l5_ran
    set l5_ran [expr {[$l5_cpu curstate] ne "halted"}]
    if {$l5_ran} { halt 1000 }
    stm32l5x.dap apcsw 0 0x40000000
}

proc l5_release {} {
    global l5_ran
    if {$l5_ran} { resume }
    set l5_ran 0
}

# SRAM and flash through their Secure aliases.
proc l5_salias {a} {
    if {$a >= 0x20000000 && $a < 0x30000000} { return [expr {$a + 0x10000000}] }
    if {$a >= 0x08000000 && $a < 0x0C000000} { return [expr {$a + 0x04000000}] }
    return $a
}

# A Secure read of a Non-secure SRAM block is illegal unless SRWILADIS, and
# Non-secure flash pages read through the Secure alias only under SECBB; both
# are opened for one access and put back.
proc l5_open {} {
    global l5_saved
    set l5_saved {}
    foreach r {0x50032C00 0x50033000} {
        set v [mrw $r]
        lappend l5_saved $r $v
        mww $r [expr {$v | 0x80000000}]
    }
    foreach r {0x500220A8 0x500220AC} {
        lappend l5_saved $r [mrw $r]
        mww $r 0xFFFFFFFF
    }
}

proc l5_close {} {
    global l5_saved
    set bad {}
    foreach {r v} $l5_saved {
        if {[catch {mww $r $v; mrw $r} got] || $got != $v} { lappend bad [format 0x%08X $r] }
    }
    set l5_saved {}
    if {[llength $bad]} { return -code error "not restored: $bad" }
}

proc l5_words {tag a w} {
    set out [format "%s 0x%08X" $tag $a]
    foreach x $w { append out [format " %08x" $x] }
    echo $out
}

# l5_held <body>: run <body> with the core held and the Secure views open;
# the views are closed whatever <body> did, and the core stays halted if
# they could not be.
proc l5_held {body} {
    if {[catch {l5_hold} e]} { return -code error "halt: $e" }
    set rc [catch {l5_open; uplevel 1 $body} r]
    if {[catch {l5_close} ce]} {
        return -code error "attribution $ce; the core stays halted"
    }
    catch {l5_release}
    return -code $rc $r
}

# l5_mem <address> <words>: L5MEM <address> <word>...
proc l5_mem {a n} {
    if {[catch {l5_held {read_memory [l5_salias $a] 32 $n}} w]} {
        echo [format "L5ERR read 0x%08X %s" $a $w]
        return
    }
    l5_words L5MEM $a $w
}

# l5_dump <file> <address> <bytes>: the bytes into <file>.
proc l5_dump {f a n} {
    if {[catch {l5_held {dump_image $f [l5_salias $a] $n}} e]} {
        echo [format "L5ERR dump 0x%08X %s" $a $e]
        return
    }
    echo [format "L5DUMP 0x%08X %d" $a $n]
}

# The option registers OPTR through WRP2BR (FLASH 0x40-0x6C).
proc l5_ob {} {
    if {[catch {read_memory 0x50022040 32 12} w]} { echo "L5ERR ob"; return }
    l5_words L5OB 0x50022040 $w
}

# The 96-bit UID answers only a Non-secure access, so one SAU region claims
# its page Non-secure for the read; DSCSR selects the Secure SAU bank.
proc l5_uid {} {
    if {[catch {l5_hold} e]} { echo "L5ERR uid halt: $e"; return }
    # Each saved register joins the undo list before it is changed, in the
    # order it must be put back; a failure anywhere restores what was saved.
    set undo {}
    set rc [catch {
        set dscsr [mrw 0xE000EE08]
        set undo [concat [list 0xE000EE08 $dscsr] $undo]
        mww 0xE000EE08 [expr {($dscsr & ~3) | 3}]
        set ctrl [mrw 0xE000EDD0]
        set rnr [mrw 0xE000EDD8]
        set undo [concat [list 0xE000EDD0 $ctrl 0xE000EDD8 $rnr] $undo]
        set r [expr {([mrw 0xE000EDD4] & 0xFF) - 1}]
        if {$r < 0} { set r 0 }
        mww 0xE000EDD8 $r
        set rbar [mrw 0xE000EDDC]
        set rlar [mrw 0xE000EDE0]
        set undo [concat [list 0xE000EDD8 $r 0xE000EDDC $rbar 0xE000EDE0 $rlar] $undo]
        mww 0xE000EDDC 0x0BFA0000
        mww 0xE000EDE0 0x0BFA0FE1
        mww 0xE000EDD0 [expr {$ctrl | 1}]
        set uid [read_memory 0x0BFA0590 32 3]
    } e]
    # DSCSR reads back only its bank select; its other bits are status.
    set bad 0
    foreach {a v} $undo {
        set m [expr {$a == 0xE000EE08 ? 3 : 0xFFFFFFFF}]
        if {[catch {mww $a $v; mrw $a} got] || ($got & $m) != ($v & $m)} { set bad 1 }
    }
    if {$bad} { echo "L5ERR uid: the SAU could not be restored; the core stays halted"; return }
    catch {l5_release}
    if {$rc} { echo "L5ERR uid $e"; return }
    l5_words L5UID 0x0BFA0590 $uid
}

# l5_obw <offset> <mask> <value>...: unlock, merge each field into its Secure
# option register, OPTSTRT, then OBL_LAUNCH, which resets the part.
proc l5_obw {args} {
    mww 0x40022008 0x45670123
    mww 0x40022008 0xCDEF89AB
    mww 0x40022010 0x08192A3B
    mww 0x40022010 0x4C5D6E7F
    foreach {off mask val} $args {
        set a [expr {0x50022000 + $off}]
        set v [mrw $a]
        mww $a [expr {($v & ~$mask) | ($val & $mask)}]
    }
    mmw 0x40022028 0x00020000 0
    set n 0
    while {([mrw 0x40022020] & 0x00010000) != 0 && $n < 200} {
        sleep 10
        incr n
    }
    set sr [mrw 0x40022020]
    echo [format "L5OBW 0x%08X" $sr]
    if {($sr & 0x000120FA) != 0} { echo "L5ERR obw"; return }
    catch {mmw 0x40022028 0x08000000 0}
}

# l5_program <erase base> <erase bytes> <file> <address>...: erase the range,
# then program only each file's bytes and verify each before the boot.
proc l5_program {base size args} {
    if {[catch {flash erase_address $base $size} e]} { echo "L5ERR erase $e"; return }
    foreach {f a} $args {
        if {[catch {flash write_image $f [l5_salias $a] bin} e]} { echo "L5ERR write $f $e"; return }
    }
    # Verified before the boot; Non-secure pages read back under SECBB.
    foreach {f a} $args {
        set rc [catch {l5_open; verify_image $f [l5_salias $a] bin} e]
        if {[catch {l5_close} ce]} { echo "L5ERR verify $f attribution $ce"; return }
        if {$rc} { echo "L5ERR verify $f $e"; return }
    }
    echo "L5PROG [expr {[llength $args] / 2}]"
}

# l5_erase_try <address> <bytes>: an erase the write protection must refuse.
proc l5_erase_try {a n} {
    if {[catch {flash erase_address [l5_salias $a] $n} e]} {
        echo "L5ERASE refused $e"
    } else {
        echo "L5ERASE done"
    }
}

# l5_boot <address>...: clear the words with the core held at reset, then a
# pin reset boots the chain.
proc l5_boot {args} {
    l5_open
    set bad {}
    foreach a $args {
        set s [l5_salias $a]
        mww $s 0
        if {[mrw $s] != 0} { lappend bad [format 0x%08X $a] }
    }
    l5_close
    if {[llength $bad]} { echo "L5ERR zero $bad"; return }
    echo "L5BOOT [llength $args]"
    reset_config srst_only srst_nogate
    reset run
}

# l5_advance <entry> <life cycle> <handoff> <address>...: from reset, stop at
# wolfTrust's entry, rewrite the handoff record's life cycle, clear the
# addresses, and resume.
proc l5_advance {entry psa handoff args} {
    global l5_cpu
    bp $entry 2 hw
    resume
    catch {wait_halt 10000}
    set pc 0
    regexp {0x[0-9a-fA-F]+} [reg pc] pc
    rbp $entry
    if {[$l5_cpu curstate] ne "halted" || $pc != $entry} { echo "L5ERR entry"; return }
    if {[mrw $handoff] != 0x5742484F || [mrw [expr {$handoff + 4}]] != 0xA8BDB7B0} {
        echo "L5ERR handoff"
        return
    }
    mww [expr {$handoff + 12}] $psa
    set got [mrw [expr {$handoff + 12}]]
    foreach a $args {
        mww $a 0
        if {[mrw $a] != 0} { echo "L5ERR clear $a"; return }
    }
    resume
    echo [format "L5ADV 0x%08X 0x%04X" $entry $got]
}
