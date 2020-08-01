// Helpful links:
// https://clojure.org/guides/learn/syntax
// https://clojure.org/reference/reader
// https://clojure.org/guides/weird_characters
// https://github.com/venantius/glow/blob/master/resources/parsers/Clojure.g4
// https://github.com/tree-sitter/tree-sitter-java/blob/master/grammar.js
// https://github.com/atom/language-clojure/blob/master/grammars/clojure.cson
// http://cljs.github.io/api/syntax/
// https://gist.github.com/Aerijo/df27228d70c633e088b0591b8857eeef
// https://github.com/Tavistock/tree-sitter-clojure

const DIGITS = token(sep1(/[0-9]+/, /_+/))

module.exports = grammar({
  name: 'lisp',

  extras: _ => [
    /(\s|,)/ // ignore whitespace and commas
  ],

  rules: {
    program: $ => repeat($._anything),

    _anything: $ => choice(
      $._literals,
      $.symbol,
      $.scoped_symbol,
      $.quote,
      $.comment,
      $.deref,
      $.list,

      $.syntax_quote,
      $.var_quote,

      $.unquote,
      $.unquote_splice,
      $.gensym,

      $.reader_conditional,
    ),

    _literals: $ => choice(
      $.nil,
      $.boolean,
      $.number,
      $.character,
      $.string,
      $.keyword,
      $.tagged_literal
    ),

    // -------------------------------------------------------------------------
    // nil + booleans
    // -------------------------------------------------------------------------

    nil: _ => 'nil',
    boolean: $ => $.true,
    true: _ => 't',

    // -------------------------------------------------------------------------
    // Numbers
    // -------------------------------------------------------------------------

    number: $ => $._number,
    _number: $ => choice(
      $.number_long,
      $.number_double,
      $.number_bigint,
      $.number_bigdecimal,
      $.number_ratio
    ),

    number_long: $ => choice($._normal_long, $._number_hex, $._number_arbitrary_radix, $._number_octal),
    _normal_long: _ => /[-+]?\d+/,
    _number_hex: _ => /-?0[xX][0-9a-fA-F]+/,
    _number_arbitrary_radix: _ => /-?\d+[rR][0-9a-zA-Z]+/,
    _number_octal: _ => /-?0\d+/,

    number_double: _ => token(
      choice(
        seq(DIGITS, '.', optional(DIGITS), optional(seq((/[eE]/), optional(choice('-', '+')), DIGITS)), optional(/[fFdD]/)),
        seq('.', DIGITS, optional(seq((/[eE]/), optional(choice('-', '+')), DIGITS)), optional(/[fFdD]/)),
        seq(DIGITS, /[eE]/, optional(choice('-', '+')), DIGITS, optional(/[fFdD]/)),
        seq(DIGITS, optional(seq((/[eE]/), optional(choice('-', '+')), DIGITS)), (/[fFdD]/))
      )),
    number_bigint: _ => /[-+]?\d+N/,
    number_bigdecimal: _ => /-?\d+\.\d+([eE][+-]?\d+)?M/,
    number_ratio: _ => /[-+]?\d+\/\d+/,

    // -------------------------------------------------------------------------
    // Character - \a
    // -------------------------------------------------------------------------

    character: $ => $._character,
    _character: $ => seq('\\', choice($._normal_char, $._special_char, $._unicode_char, $._octal_char)),
    _normal_char: _ => /./,
    _special_char: _ => choice('newline', 'space', 'tab', 'formfeed', 'backspace', 'return'),
    _unicode_char: $ => seq('u', $._hex_char, $._hex_char, $._hex_char, $._hex_char),
    _hex_char: _ => /[A-Fa-f0-9]/,
    _octal_char: $ => seq('o', $._octal_num),
    _octal_num: _ => choice(/[0-3][0-7][0-7]/, /[0-7][0-7]/, /[0-7]/),

    // -------------------------------------------------------------------------
    // Strings - ""
    // -------------------------------------------------------------------------

    string: $ => $._string,
    _string: _ => seq('"', repeat(choice('\\"', /[^"]/)), '"'),


    // -------------------------------------------------------------------------
    // Quote - '() (quote)
    // -------------------------------------------------------------------------

    // NOTE: would it be useful to distinguish between these two?
    quote: $ => $._quote,
    _quote: $ => choice(
      seq("'", $._anything),
      seq('(quote', $._anything, ')')
    ),

    // -------------------------------------------------------------------------
    // Keywords - :foo
    // -------------------------------------------------------------------------

    _keyword: $ => seq(':', $.keyword),
    keyword: $ => choice(
      $._unqualified_keyword,
    ),

    _unqualified_keyword: $ => seq(':', $._keyword_chars),
    _keyword_chars: _ => /[a-zA-Z0-9\-_\!\+\.][a-zA-Z0-9\-_\!\+\.\?]*/,

    // -------------------------------------------------------------------------
    // Symbols - foo
    // -------------------------------------------------------------------------

    symbol: $ => $._symbol,
    _symbol: $ => choice(
      $._symbol_chars,
      $.qualified_symbol
    ),

    // -------------------------------------------------------------------------
    // Scoped symbols - foo
    // -------------------------------------------------------------------------

    scoped_symbol: $ => prec.left(3, seq($.package, choice(':', '::'), $.symbol)),
    package: $ => prec.left(3,seq( $.subpackage, repeat(seq('.', $.subpackage)))),
    subpackage: _ => prec.left(3,/[a-zA-Z0-9\-_\!\+][a-zA-Z0-9\-_\!\+\?]*/),
    // reference: https://clojure.org/reference/reader#_symbols
    _symbol_chars: _ => /[a-zA-Z0-9\-_\!\+][a-zA-Z0-9\-_\!\+\?]*/,
    qualified_symbol: $ => $._qualified_symbol,
    _qualified_symbol: $ => seq($._symbol_chars, '/', $._symbol_chars),

    // TODO: "new" symbol, single dot, double dot, memfn, doto
    // https://github.com/oakmac/tree-sitter-clojure/issues/13

    // -------------------------------------------------------------------------
    // List - ()
    // -------------------------------------------------------------------------

    list: $ => $._list,
    _list: $ => seq('(', optional(seq($._anything, repeat1(seq(' ', $._anything)))), ')'),


    // -------------------------------------------------------------------------
    // Hash Map - {}
    // -------------------------------------------------------------------------

    hash_map: $ => $._hash_map,
    _hash_map: $ => choice(
      seq('{', repeat($._hash_map_kv_pair), '}'),
      $.namespace_map
    ),
    namespace_map: $ => choice(
      seq('#::{', repeat($._hash_map_kv_pair), '}'),
      seq(/\#:[a-zA-Z\*\+\!\-_\?][a-zA-Z0-9\*\+\!\-_\?\':]*/, '{', repeat($._hash_map_kv_pair), '}')
    ),
    _hash_map_kv_pair: $ => seq($._hash_map_key, $._hash_map_value),
    _hash_map_key: $ => $._anything,
    _hash_map_value: $ => $._anything,

    // -------------------------------------------------------------------------
    // Set - #{}
    // -------------------------------------------------------------------------

    set: $ => $._set,
    _set: $ => seq('#{', repeat($._anything), '}'),

    // -------------------------------------------------------------------------
    // Comments
    // -------------------------------------------------------------------------

    comment: $ => choice($.semicolon, $.shebang_line, $.ignore_form, $.comment_macro),
    semicolon: $ => seq(';', /.*/),
    shebang_line: $ => seq('#!', /.*/),
    ignore_form: $ => seq('#_', $._anything),
    comment_macro: $ => seq('(', 'comment', repeat($._anything), ')'),

    // -------------------------------------------------------------------------
    // Functions
    // -------------------------------------------------------------------------

    //_functions: $ => choice($.anonymous_function, $.shorthand_function, $.defn),

    //anonymous_function: $ => seq('(', 'fn', optional($.function_name), $._after_the_fn_name, ')'),
    //_after_the_fn_name: $ => choice($._single_arity_fn, $._multi_arity_fn),
    //function_name: $ => $.symbol,
    //_multi_arity_fn: $ => repeat1(seq('(', $._single_arity_fn, ')')),

    // NOTE: I don't think we need to handle condition-map here explicitly
    //       it will just be detected as (hash_map) inside the function body
    //function_body: $ => repeat1($._anything),


    //shorthand_function: $ => seq('#(', repeat($._anything), ')'),
    //shorthand_function_arg: $ => /%[1-9&]*/,

    //defn: $ => seq('(', choice('defn', 'defn-'),
                        //optional($.metadata),
                        //$.function_name,
                        //optional($.docstring),
                        //optional($.attr_map),
                        //$._after_the_fn_name, ')'),
    //docstring: $ => $.string,
    //attr_map: $ => $.hash_map,

    // -------------------------------------------------------------------------
    // Metadata
    // -------------------------------------------------------------------------

    //metadata: $ => choice(repeat1($.metadata_shorthand), $._metadata_map),
    //_metadata_map: $ => seq('^', $.hash_map),
    //// NOTE: would it be useful to expose these as separate node types?
    //metadata_shorthand: $ => choice(
      //seq('^:', $._keyword_chars),
      //seq('^"', repeat(choice('\\"', /[^"]/)), '"'),
      //seq('^', $._symbol_chars)
    //),

    // -------------------------------------------------------------------------
    // Syntax Quote and macro-related friends
    // -------------------------------------------------------------------------

    syntax_quote: $ => seq('`', $._anything),
    var_quote: $ => seq("#'", $.symbol),
    unquote: $ => seq('~', $._anything),
    unquote_splice: $ => seq('~@', $._anything),
    gensym: _ => /[a-zA-Z\*\+\!\-_\?][a-zA-Z0-9\*\+\!\-_\?\':]*\#/,

    // -------------------------------------------------------------------------
    // Deref
    // -------------------------------------------------------------------------

    // NOTE: presumably a list here would evaluate to something that can be derefed
    deref: $ => seq('@', choice($.symbol, $.list)),

    // -------------------------------------------------------------------------
    // Tagged Literal - #inst, #uuid, #foo/bar
    // -------------------------------------------------------------------------

    tagged_literal: $ => seq('#', choice($._symbol_chars, $._qualified_symbol), $._anything),

    // -------------------------------------------------------------------------
    // Reader Conditional - #?, #?@
    // -------------------------------------------------------------------------

    // NOTE: maybe we should identify "clojure_part", "cljs_part", etc here?
    reader_conditional: $ => seq($._reader_conditional_symbol, '(', repeat(seq($.keyword, $._anything)), ')'),

    // NOTE: I don't think we really need to distinguish between these two
    _reader_conditional_symbol: $ => choice('#?', '#?@'),
  }
})

function sep1 (rule, separator) {
  return seq(rule, repeat(seq(separator, rule)))
}
