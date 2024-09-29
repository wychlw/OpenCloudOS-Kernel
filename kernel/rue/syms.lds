SECTIONS
{
	.data.rue..ksyms : {
		. = ALIGN(8);
		__rue_ksyms_start = .;
		*(.data.rue..ksyms);
		__rue_ksyms_end = .;
	}
}
