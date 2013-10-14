#!/usr/bin/perl
## --------------------------------------------------------------------------
##
##   Copyright 1996-2013 The NASM Authors - All Rights Reserved
##   See the file AUTHORS included with the NASM distribution for
##   the specific copyright holders.
##
##   Redistribution and use in source and binary forms, with or without
##   modification, are permitted provided that the following
##   conditions are met:
##
##   * Redistributions of source code must retain the above copyright
##     notice, this list of conditions and the following disclaimer.
##   * Redistributions in binary form must reproduce the above
##     copyright notice, this list of conditions and the following
##     disclaimer in the documentation and/or other materials provided
##     with the distribution.
##
##     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
##     CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
##     INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
##     MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
##     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
##     CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
##     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
##     NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
##     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
##     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
##     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
##     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
##     EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##
## --------------------------------------------------------------------------

#
# Here we generate instrcution template flags. Note we assume that at moment
# less than 128 bits are used for all flags. If needed it can be extended
# arbitrary, but it'll be needed to extend arrays (they are 4 32 bit elements
# by now).

#
# The order does matter here. We use some predefined masks to quick test
# for a set of flags, so be carefull moving bits (and
# don't forget to update C code generation then).
my %insns_flag_bit = (
    #
    # dword bound, index 0 - specific flags
    #
    "SM"                => [  0, "size match"],
    "SM2"               => [  1, "size match first two operands"],
    "SB"                => [  2, "unsized operands can't be non-byte"],
    "SW"                => [  3, "unsized operands can't be non-word"],
    "SD"                => [  4, "unsized operands can't be non-dword"],
    "SQ"                => [  5, "unsized operands can't be non-qword"],
    "SO"                => [  6, "unsized operands can't be non-oword"],
    "SY"                => [  7, "unsized operands can't be non-yword"],
    "SZ"                => [  8, "unsized operands can't be non-zword"],
    "SIZE"              => [  9, "unsized operands must match the bitsize"],
    "SX"                => [ 10, "unsized operands not allowed"],
    "AR0"               => [ 11, "SB, SW, SD applies to argument 0"],
    "AR1"               => [ 12, "SB, SW, SD applies to argument 1"],
    "AR2"               => [ 13, "SB, SW, SD applies to argument 2"],
    "AR3"               => [ 14, "SB, SW, SD applies to argument 3"],
    "AR4"               => [ 15, "SB, SW, SD applies to argument 4"],
    "OPT"               => [ 16, "optimizing assembly only"],

    #
    # dword bound, index 1 - instruction filtering flags
    #
    "PRIV"              => [ 32, "it's a privileged instruction"],
    "SMM"               => [ 33, "it's only valid in SMM"],
    "PROT"              => [ 34, "it's protected mode only"],
    "LOCK"              => [ 35, "lockable if operand 0 is memory"],
    "NOLONG"            => [ 36, "it's not available in long mode"],
    "LONG"              => [ 37, "long mode instruction"],
    "NOHLE"             => [ 38, "HLE prefixes forbidden"],
    "UNDOC"             => [ 39, "it's an undocumented instruction"],
    "HLE"               => [ 40, "HLE prefixed instruction"],
    "FPU"               => [ 41, "it's an FPU instruction"],
    "MMX"               => [ 42, "it's an MMX instruction"],
    "3DNOW"             => [ 43, "it's a 3DNow! instruction"],
    "SSE"               => [ 44, "it's a SSE (KNI, MMX2) instruction"],
    "SSE2"              => [ 45, "it's a SSE2 instruction"],
    "SSE3"              => [ 46, "it's a SSE3 (PNI) instruction"],
    "VMX"               => [ 47, "it's a VMX instruction"],
    "SSSE3"             => [ 48, "it's an SSSE3 instruction"],
    "SSE4A"             => [ 49, "AMD SSE4a"],
    "SSE41"             => [ 50, "it's an SSE4.1 instruction"],
    "SSE42"             => [ 51, ""],
    "SSE5"              => [ 52, ""],
    "AVX"               => [ 53, "it's an AVX (128b) instruction"],
    "AVX2"              => [ 54, "it's an AVX2 (256b) instruction"],
    "FMA"               => [ 55, ""],
    "BMI1"              => [ 56, ""],
    "BMI2"              => [ 57, ""],
    "TBM"               => [ 58, ""],
    "RTM"               => [ 59, ""],
    "INVPCID"           => [ 60, ""],

    #
    # dword bound, index 2 - instruction filtering flags
    #
    "AVX512"            => [ 64, "it's an AVX-512F (512b) instruction"],
    "AVX512CD"          => [ 65, "AVX-512 Conflict Detection insns"],
    "AVX512ER"          => [ 66, "AVX-512 Exponential and Reciprocal"],
    "AVX512PF"          => [ 67, "AVX-512 Prefetch instructions"],

    #
    # dword bound, index 3 - cpu type flags
    #
    "8086"              => [ 96, "8086 instruction"],
    "186"               => [ 97, "186+ instruction"],
    "286"               => [ 98, "286+ instruction"],
    "386"               => [ 99, "386+ instruction"],
    "486"               => [100, "486+ instruction"],
    "PENT"              => [101, "Pentium instruction"],
    "P6"                => [102, "P6 instruction"],
    "KATMAI"            => [103, "Katmai instructions"],
    "WILLAMETTE"        => [104, "Willamette instructions"],
    "PRESCOTT"          => [105, "Prescott instructions"],
    "X86_64"            => [106, "x86-64 instruction (long or legacy mode)"],
    "NEHALEM"           => [107, "Nehalem instruction"],
    "WESTMERE"          => [108, "Westmere instruction"],
    "SANDYBRIDGE"       => [109, "Sandy Bridge instruction"],
    "FUTURE"            => [110, "Future processor (not yet disclosed)"],
    "IA64"              => [111, "IA64 instructions (in x86 mode)"],
    "CYRIX"             => [112, "Cyrix-specific instruction"],
    "AMD"               => [113, "AMD-specific instruction"],
);

my %insns_flag_hash = ();
my @insns_flag_values = ();

sub insns_flag_index(@) {
    return undef if $_[0] eq "ignore";

    my @prekey = sort(@_);
    my $key = join("", @prekey);

    if (not defined($insns_flag_hash{$key})) {
        my @newkey = ([], [], [], []);
        my $str = "";

        for my $i (@prekey) {
            die "No key for $i\n" if not defined($insns_flag_bit{$i});
            if ($insns_flag_bit{$i}[0] <       32) {
                push @newkey[0], $insns_flag_bit{$i}[0] -  0;
            } elsif ($insns_flag_bit{$i}[0] <  64) {
                push @newkey[1], $insns_flag_bit{$i}[0] - 32;
            } elsif ($insns_flag_bit{$i}[0] <  96) {
                push @newkey[2], $insns_flag_bit{$i}[0] - 64;
            } elsif ($insns_flag_bit{$i}[0] < 128) {
                push @newkey[3], $insns_flag_bit{$i}[0] - 96;
            } else {
                die "Key value is too big ", $insns_flag_bit{$i}[0], "\n";
            }
        }

        for my $j (0 .. $#newkey) {
            my $v = "";
            if (scalar(@{$newkey[$j]})) {
                $v = join(" | ", map { map { sprintf("(UINT32_C(1) << %d)", $_) } @$_; } $newkey[$j]);
            } else {
                $v = "0";
            }
            $str .= sprintf(".field[%d] = %s, ", $j, $v);
        }

        push @insns_flag_values, $str;
        $insns_flag_hash{$key} = $#insns_flag_values;
    }

    return $insns_flag_hash{$key};
}

sub write_iflags() {
    print STDERR "Writing iflag.h ...\n";

    open N, ">iflag.h";

    print N "/* This file is auto-generated. Don't edit. */\n";
    print N "#ifndef NASM_IFLAG_H__\n";
    print N "#define NASM_IFLAG_H__\n\n";

    print N "#include <inttypes.h>\n";
    print N "#include \"compiler.h\"\n\n";

    print N "/*\n";
    print N " * Instruction template flags. These specify which processor\n";
    print N " * targets the instruction is eligible for, whether it is\n";
    print N " * privileged or undocumented, and also specify extra error\n";
    print N " * checking on the matching of the instruction.\n";
    print N " *\n";
    print N " * IF_SM stands for Size Match: any operand whose size is not\n";
    print N " * explicitly specified by the template is `really' intended to be\n";
    print N " * the same size as the first size-specified operand.\n";
    print N " * Non-specification is tolerated in the input instruction, but\n";
    print N " * _wrong_ specification is not.\n";
    print N " *\n";
    print N " * IF_SM2 invokes Size Match on only the first _two_ operands, for\n";
    print N " * three-operand instructions such as SHLD: it implies that the\n";
    print N " * first two operands must match in size, but that the third is\n";
    print N " * required to be _unspecified_.\n";
    print N " *\n";
    print N " * IF_SB invokes Size Byte: operands with unspecified size in the\n";
    print N " * template are really bytes, and so no non-byte specification in\n";
    print N " * the input instruction will be tolerated. IF_SW similarly invokes\n";
    print N " * Size Word, and IF_SD invokes Size Doubleword.\n";
    print N " *\n";
    print N " * (The default state if neither IF_SM nor IF_SM2 is specified is\n";
    print N " * that any operand with unspecified size in the template is\n";
    print N " * required to have unspecified size in the instruction too...)\n";
    print N " *\n";
    print N " * iflags_t is defined to store these flags.\n";
    print N " */\n";
    foreach my $key (sort { $insns_flag_bit{$a}[0] <=> $insns_flag_bit{$b}[0] } keys(%insns_flag_bit)) {
        print N sprintf("#define IF_%-16s (%3d) /* %-64s */\n",
            $key, $insns_flag_bit{$key}[0], $insns_flag_bit{$key}[1]);
    }

    print N "\n";
    print N "typedef struct {\n";
    print N "    uint32_t field[4];\n";
    print N "} iflag_t;\n\n";

    print N "\n";
    print N sprintf("extern iflag_t insns_flags[%d];\n\n", $#insns_flag_values + 1);

    print N "#define IF_GENBIT(bit)          (UINT32_C(1) << (bit))\n\n";

    print N "static inline unsigned int iflag_test(iflag_t *f,unsigned int bit)\n";
    print N "{\n";
    print N "    unsigned int index = bit / 32;\n";
    print N "    return f->field[index] & (UINT32_C(1) << (bit - (index * 32)));\n";
    print N "}\n\n";

    print N "static inline void iflag_set(iflag_t *f, unsigned int bit)\n";
    print N "{\n";
    print N "    unsigned int index = bit / 32;\n";
    print N "    f->field[index] |= (UINT32_C(1) << (bit - (index * 32)));\n";
    print N "}\n\n";

    print N "static inline void iflag_clear(iflag_t *f, unsigned int bit)\n";
    print N "{\n";
    print N "    unsigned int index = bit / 32;\n";
    print N "    f->field[index] &= ~(UINT32_C(1) << (bit - (index * 32)));\n";
    print N "}\n\n";

    print N "/* Use this helper to test instruction template flags */\n";
    print N "#define itemp_has(itemp, bit)   iflag_test(&insns_flags[(itemp)->iflag_idx], bit)\n\n";

    print N "/* Some helpers which are to work with predefined masks */\n";
    print N "#define IF_SMASK        \\\n";
    print N "    (IF_GENBIT(IF_SB)  |\\\n";
    print N "     IF_GENBIT(IF_SW)  |\\\n";
    print N "     IF_GENBIT(IF_SD)  |\\\n";
    print N "     IF_GENBIT(IF_SQ)  |\\\n";
    print N "     IF_GENBIT(IF_SO)  |\\\n";
    print N "     IF_GENBIT(IF_SY)  |\\\n";
    print N "     IF_GENBIT(IF_SZ))\n";
    print N "#define IF_ARMASK       \\\n";
    print N "    (IF_GENBIT(IF_AR0) |\\\n";
    print N "     IF_GENBIT(IF_AR1) |\\\n";
    print N "     IF_GENBIT(IF_AR2) |\\\n";
    print N "     IF_GENBIT(IF_AR3) |\\\n";
    print N "     IF_GENBIT(IF_AR4))\n";

    print N "\n";
    print N "#define itemp_smask(itemp)      (insns_flags[(itemp)->iflag_idx].field[0] & IF_SMASK)\n";
    print N "#define itemp_arg(itemp)        (((insns_flags[(itemp)->iflag_idx].field[0] & IF_ARMASK) >> IF_AR0) - 1)\n";

    print N "\n";
    print N "#define IF_CPUMASK               \\\n";
    print N "    (IF_GENBIT(IF_8086)         |\\\n";
    print N "     IF_GENBIT(IF_186)          |\\\n";
    print N "     IF_GENBIT(IF_286)          |\\\n";
    print N "     IF_GENBIT(IF_386)          |\\\n";
    print N "     IF_GENBIT(IF_486)          |\\\n";
    print N "     IF_GENBIT(IF_PENT)         |\\\n";
    print N "     IF_GENBIT(IF_P6)           |\\\n";
    print N "     IF_GENBIT(IF_KATMAI)       |\\\n";
    print N "     IF_GENBIT(IF_WILLAMETTE)   |\\\n";
    print N "     IF_GENBIT(IF_PRESCOTT)     |\\\n";
    print N "     IF_GENBIT(IF_X86_64)       |\\\n";
    print N "     IF_GENBIT(IF_NEHALEM)      |\\\n";
    print N "     IF_GENBIT(IF_WESTMERE)     |\\\n";
    print N "     IF_GENBIT(IF_SANDYBRIDGE)  |\\\n";
    print N "     IF_GENBIT(IF_FUTURE)       |\\\n";
    print N "     IF_GENBIT(IF_IA64)         |\\\n";
    print N "     IF_GENBIT(IF_CYRIX)        |\\\n";
    print N "     IF_GENBIT(IF_AMD))\n";
    # FIXME These are not yet addressed
    # IF_PLEVEL
    # IF_SPMASK
    # IF_PFMASK

    print N "\n";
    print N "#endif /* NASM_IFLAG_H__ */\n";
    close N;

    print STDERR "Writing iflag.c ...\n";

    open N, ">iflag.c";

    print N "/* This file is auto-generated. Don't edit. */\n";
    print N "#include \"iflag.h\"\n\n";
    print N "/* Global flags referenced from instruction templates */\n";
    print N sprintf("iflag_t insns_flags[%d] = {\n", $#insns_flag_values + 1);
    foreach my $i (0 .. $#insns_flag_values) {
        print N sprintf("    [%8d] = { %s },\n", $i, $insns_flag_values[$i]);
    }
    print N "};\n\n";
    close N;
}

1;
