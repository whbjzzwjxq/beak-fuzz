from zkvm_fuzzer_utils.rust.common import comment_func_call_stmts


def test_comment_func_call_stmts():
    rust_source = """
    let r = 0;
    let x = 1;
    assert_eq!(
        r,
        x,
    );
    print!("{} == {}", r, x);

    some_weird_function   (
        "I am a weird custom macro",
        "Hello", "World", "!",
        0xdeadbeed    );

"""

    assert (
        comment_func_call_stmts("assert_eq!", rust_source)
        == """
    let r = 0;
    let x = 1;
    /* assert_eq!(
        r,
        x,
    ); */
    print!("{} == {}", r, x);

    some_weird_function   (
        "I am a weird custom macro",
        "Hello", "World", "!",
        0xdeadbeed    );

"""
    ), "'assert_eq!' commenting failed!"

    assert (
        comment_func_call_stmts("print!", rust_source)
        == """
    let r = 0;
    let x = 1;
    assert_eq!(
        r,
        x,
    );
    /* print!("{} == {}", r, x); */

    some_weird_function   (
        "I am a weird custom macro",
        "Hello", "World", "!",
        0xdeadbeed    );

"""
    ), "'print!' commenting failed"

    assert (
        comment_func_call_stmts("some_weird_function", rust_source)
        == """
    let r = 0;
    let x = 1;
    assert_eq!(
        r,
        x,
    );
    print!("{} == {}", r, x);

    /* some_weird_function(
        "I am a weird custom macro",
        "Hello", "World", "!",
        0xdeadbeed    ); */

"""
    ), "'some_weird_function' commenting failed"
