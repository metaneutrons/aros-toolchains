template<typename T> struct ArosBox
{
    T value;
    constexpr T doubled() const { return value + value; }
};

extern "C" unsigned long aros_toolchain_cxx_probe(unsigned long value)
{
    return ArosBox<unsigned long>{value}.doubled();
}
