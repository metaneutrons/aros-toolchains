typedef unsigned long aros_word_t;

aros_word_t aros_toolchain_c_probe(aros_word_t value)
{
    return (value << 1) ^ (value >> 1);
}
