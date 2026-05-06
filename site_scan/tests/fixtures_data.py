"""Inline byte-content for test fixture files. Committed here (rather than as
binary files) so test data is reviewable in diffs and reproducible regardless
of TLSH compile-time flags. Each value is bytes that hashes to a valid TLSH
digest (length >= 50, sufficient entropy).

Note: the spec's original fixture data used repetitive content (b"echo 'aaaa';\n" * 30)
which lacks enough variation for TLSH. These fixtures use sequential indices to ensure
sufficient entropy for TLSH hashing while remaining readable in diffs.
"""

# These contents are used to compute digests at test time.
FILES = {
    # PHP-like content with sequential variation for TLSH entropy
    "alpha.php":   b"<?php\n" + b"".join(f"echo 'item{i:03d}';\n".encode() for i in range(40)) + b'echo "end";\n',
    "alpha2.php":  b"<?php\n" + b"".join(f"echo 'item{i:03d}';\n".encode() for i in range(40)) + b'echo "fin";\n',  # near-clone of alpha.php
    "beta.php":    b"<?php\n" + b"".join(f"function f{i:03d}(){{ return {i}; }}\n".encode() for i in range(30)) + b'echo "end";\n',
    "gamma.html":  b"<html><body>\n" + b"".join(f'<p class="item-{i:03d}">Hello world {i}</p>\n'.encode() for i in range(25)) + b"</body></html>",
    "delta.js":    b"// header\n" + b"".join(f"var x{i:03d} = {i};\nfunction f{i:03d}(){{return x{i:03d};}}\n".encode() for i in range(20)),
    "epsilon.txt": (b"plain text fixture, not in default extension set.\n" +
                    b"".join(f"line {i:04d}: the quick brown fox jumps over the lazy dog.\n".encode() for i in range(15))),
    "tiny.php":    b"<?php echo 1; ?>",  # under MIN_DATA_LENGTH (50)
}
