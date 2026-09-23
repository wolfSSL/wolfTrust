int wt_c11_probe(int value)
{
    return _Generic(value, int: 1, default: 0);
}
