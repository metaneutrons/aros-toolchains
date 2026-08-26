template<typename T> struct ArosBox
{
    T value;
    constexpr T doubled() const { return value + value; }
};

static unsigned long aros_toolchain_constructor_value;

struct ArosConstructorProbe
{
    ArosConstructorProbe() { aros_toolchain_constructor_value = 1; }
};

static ArosConstructorProbe aros_toolchain_constructor_probe;

extern "C" unsigned long aros_toolchain_cxx_probe(unsigned long value)
{
    return ArosBox<unsigned long>{value}.doubled() + aros_toolchain_constructor_value;
}
