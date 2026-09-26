typedef unsigned long aros_word_t;

/* A direct link through collect-aros must materialise this symbol set. */
__asm__(
    ".weak __TOOLCHAIN__symbol_set_handler_missing\n"
    "__TOOLCHAIN__symbol_set_handler_missing=0\n");

static void aros_toolchain_set_member(void) {}

__attribute__((used, section(".aros.set.TOOLCHAIN.10")))
static void (*const aros_toolchain_set_entry)(void) = aros_toolchain_set_member;

aros_word_t aros_toolchain_c_probe(aros_word_t value)
{
    return (value << 1) ^ (value >> 1);
}
