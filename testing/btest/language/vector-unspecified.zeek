# @TEST-EXEC-FAIL: unset ZEEK_ALLOW_INIT_ERRORS && zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

# Test assignment behavior of unspecified vectors
local a = vector();

a[0] = 5;
a[1] = "Hi";
a[2] = 127.0.0.1;

print a;
