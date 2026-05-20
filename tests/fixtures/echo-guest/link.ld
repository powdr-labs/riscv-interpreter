/* Mirror OpenVM's segment layout closely enough for our simulator. */
ENTRY(_start)

MEMORY {
    ROM (rx)  : ORIGIN = 0x00200800, LENGTH = 4M
    DATA (rwx): ORIGIN = 0x00400000, LENGTH = 4M
}

SECTIONS {
    .text   : { *(.text._start) *(.text*) } > ROM
    .rodata : { *(.rodata*) }               > ROM
    .data   : { *(.data*) }                 > DATA
    .bss    : { *(.bss*) *(COMMON) }        > DATA
}
