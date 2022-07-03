// A representation of the abstract syntax of the Common Expression Language.

/// An expression together with source information as returned by the parser.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ParsedExpr {
    /// The parsed expression.
    #[prost(message, optional, tag="2")]
    pub expr: ::core::option::Option<Expr>,
    /// The source info derived from input that generated the parsed `expr`.
    #[prost(message, optional, tag="3")]
    pub source_info: ::core::option::Option<SourceInfo>,
}
/// An abstract representation of a common expression.
///
/// Expressions are abstractly represented as a collection of identifiers,
/// select statements, function calls, literals, and comprehensions. All
/// operators with the exception of the '.' operator are modelled as function
/// calls. This makes it easy to represent new operators into the existing AST.
///
/// All references within expressions must resolve to a \[Decl][google.api.expr.v1alpha1.Decl\] provided at
/// type-check for an expression to be valid. A reference may either be a bare
/// identifier `name` or a qualified identifier `google.api.name`. References
/// may either refer to a value or a function declaration.
///
/// For example, the expression `google.api.name.startsWith('expr')` references
/// the declaration `google.api.name` within a \[Expr.Select][google.api.expr.v1alpha1.Expr.Select\] expression, and
/// the function declaration `startsWith`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Expr {
    /// Required. An id assigned to this node by the parser which is unique in a
    /// given expression tree. This is used to associate type information and other
    /// attributes to a node in the parse tree.
    #[prost(int64, tag="2")]
    pub id: i64,
    /// Required. Variants of expressions.
    #[prost(oneof="expr::ExprKind", tags="3, 4, 5, 6, 7, 8, 9")]
    pub expr_kind: ::core::option::Option<expr::ExprKind>,
}
/// Nested message and enum types in `Expr`.
pub mod expr {
    /// An identifier expression. e.g. `request`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Ident {
        /// Required. Holds a single, unqualified identifier, possibly preceded by a
        /// '.'.
        ///
        /// Qualified names are represented by the \[Expr.Select][google.api.expr.v1alpha1.Expr.Select\] expression.
        #[prost(string, tag="1")]
        pub name: ::prost::alloc::string::String,
    }
    /// A field selection expression. e.g. `request.auth`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Select {
        /// Required. The target of the selection expression.
        ///
        /// For example, in the select expression `request.auth`, the `request`
        /// portion of the expression is the `operand`.
        #[prost(message, optional, boxed, tag="1")]
        pub operand: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// Required. The name of the field to select.
        ///
        /// For example, in the select expression `request.auth`, the `auth` portion
        /// of the expression would be the `field`.
        #[prost(string, tag="2")]
        pub field: ::prost::alloc::string::String,
        /// Whether the select is to be interpreted as a field presence test.
        ///
        /// This results from the macro `has(request.auth)`.
        #[prost(bool, tag="3")]
        pub test_only: bool,
    }
    /// A call expression, including calls to predefined functions and operators.
    ///
    /// For example, `value == 10`, `size(map_value)`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Call {
        /// The target of an method call-style expression. For example, `x` in
        /// `x.f()`.
        #[prost(message, optional, boxed, tag="1")]
        pub target: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// Required. The name of the function or method being called.
        #[prost(string, tag="2")]
        pub function: ::prost::alloc::string::String,
        /// The arguments.
        #[prost(message, repeated, tag="3")]
        pub args: ::prost::alloc::vec::Vec<super::Expr>,
    }
    /// A list creation expression.
    ///
    /// Lists may either be homogenous, e.g. `[1, 2, 3]`, or heterogeneous, e.g.
    /// `dyn([1, 'hello', 2.0])`
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CreateList {
        /// The elements part of the list.
        #[prost(message, repeated, tag="1")]
        pub elements: ::prost::alloc::vec::Vec<super::Expr>,
    }
    /// A map or message creation expression.
    ///
    /// Maps are constructed as `{'key_name': 'value'}`. Message construction is
    /// similar, but prefixed with a type name and composed of field ids:
    /// `types.MyType{field_id: 'value'}`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CreateStruct {
        /// The type name of the message to be created, empty when creating map
        /// literals.
        #[prost(string, tag="1")]
        pub message_name: ::prost::alloc::string::String,
        /// The entries in the creation expression.
        #[prost(message, repeated, tag="2")]
        pub entries: ::prost::alloc::vec::Vec<create_struct::Entry>,
    }
    /// Nested message and enum types in `CreateStruct`.
    pub mod create_struct {
        /// Represents an entry.
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Entry {
            /// Required. An id assigned to this node by the parser which is unique
            /// in a given expression tree. This is used to associate type
            /// information and other attributes to the node.
            #[prost(int64, tag="1")]
            pub id: i64,
            /// Required. The value assigned to the key.
            #[prost(message, optional, tag="4")]
            pub value: ::core::option::Option<super::super::Expr>,
            /// The `Entry` key kinds.
            #[prost(oneof="entry::KeyKind", tags="2, 3")]
            pub key_kind: ::core::option::Option<entry::KeyKind>,
        }
        /// Nested message and enum types in `Entry`.
        pub mod entry {
            /// The `Entry` key kinds.
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum KeyKind {
                /// The field key for a message creator statement.
                #[prost(string, tag="2")]
                FieldKey(::prost::alloc::string::String),
                /// The key expression for a map creation statement.
                #[prost(message, tag="3")]
                MapKey(super::super::super::Expr),
            }
        }
    }
    /// A comprehension expression applied to a list or map.
    ///
    /// Comprehensions are not part of the core syntax, but enabled with macros.
    /// A macro matches a specific call signature within a parsed AST and replaces
    /// the call with an alternate AST block. Macro expansion happens at parse
    /// time.
    ///
    /// The following macros are supported within CEL:
    ///
    /// Aggregate type macros may be applied to all elements in a list or all keys
    /// in a map:
    ///
    /// *  `all`, `exists`, `exists_one` -  test a predicate expression against
    ///    the inputs and return `true` if the predicate is satisfied for all,
    ///    any, or only one value `list.all(x, x < 10)`.
    /// *  `filter` - test a predicate expression against the inputs and return
    ///    the subset of elements which satisfy the predicate:
    ///    `payments.filter(p, p > 1000)`.
    /// *  `map` - apply an expression to all elements in the input and return the
    ///    output aggregate type: `[1, 2, 3].map(i, i * i)`.
    ///
    /// The `has(m.x)` macro tests whether the property `x` is present in struct
    /// `m`. The semantics of this macro depend on the type of `m`. For proto2
    /// messages `has(m.x)` is defined as 'defined, but not set`. For proto3, the
    /// macro tests whether the property is set to its default. For map and struct
    /// types, the macro tests whether the property `x` is defined on `m`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Comprehension {
        /// The name of the iteration variable.
        #[prost(string, tag="1")]
        pub iter_var: ::prost::alloc::string::String,
        /// The range over which var iterates.
        #[prost(message, optional, boxed, tag="2")]
        pub iter_range: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// The name of the variable used for accumulation of the result.
        #[prost(string, tag="3")]
        pub accu_var: ::prost::alloc::string::String,
        /// The initial value of the accumulator.
        #[prost(message, optional, boxed, tag="4")]
        pub accu_init: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// An expression which can contain iter_var and accu_var.
        ///
        /// Returns false when the result has been computed and may be used as
        /// a hint to short-circuit the remainder of the comprehension.
        #[prost(message, optional, boxed, tag="5")]
        pub loop_condition: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// An expression which can contain iter_var and accu_var.
        ///
        /// Computes the next value of accu_var.
        #[prost(message, optional, boxed, tag="6")]
        pub loop_step: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
        /// An expression which can contain accu_var.
        ///
        /// Computes the result.
        #[prost(message, optional, boxed, tag="7")]
        pub result: ::core::option::Option<::prost::alloc::boxed::Box<super::Expr>>,
    }
    /// Required. Variants of expressions.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ExprKind {
        /// A literal expression.
        #[prost(message, tag="3")]
        ConstExpr(super::Constant),
        /// An identifier expression.
        #[prost(message, tag="4")]
        IdentExpr(Ident),
        /// A field selection expression, e.g. `request.auth`.
        #[prost(message, tag="5")]
        SelectExpr(::prost::alloc::boxed::Box<Select>),
        /// A call expression, including calls to predefined functions and operators.
        #[prost(message, tag="6")]
        CallExpr(::prost::alloc::boxed::Box<Call>),
        /// A list creation expression.
        #[prost(message, tag="7")]
        ListExpr(CreateList),
        /// A map or message creation expression.
        #[prost(message, tag="8")]
        StructExpr(CreateStruct),
        /// A comprehension expression.
        #[prost(message, tag="9")]
        ComprehensionExpr(::prost::alloc::boxed::Box<Comprehension>),
    }
}
/// Represents a primitive literal.
///
/// Named 'Constant' here for backwards compatibility.
///
/// This is similar as the primitives supported in the well-known type
/// `google.protobuf.Value`, but richer so it can represent CEL's full range of
/// primitives.
///
/// Lists and structs are not included as constants as these aggregate types may
/// contain \[Expr][google.api.expr.v1alpha1.Expr\] elements which require evaluation and are thus not constant.
///
/// Examples of literals include: `"hello"`, `b'bytes'`, `1u`, `4.2`, `-2`,
/// `true`, `null`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Constant {
    /// Required. The valid constant kinds.
    #[prost(oneof="constant::ConstantKind", tags="1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub constant_kind: ::core::option::Option<constant::ConstantKind>,
}
/// Nested message and enum types in `Constant`.
pub mod constant {
    /// Required. The valid constant kinds.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConstantKind {
        /// null value.
        #[prost(enumeration="::prost_types::NullValue", tag="1")]
        NullValue(i32),
        /// boolean value.
        #[prost(bool, tag="2")]
        BoolValue(bool),
        /// int64 value.
        #[prost(int64, tag="3")]
        Int64Value(i64),
        /// uint64 value.
        #[prost(uint64, tag="4")]
        Uint64Value(u64),
        /// double value.
        #[prost(double, tag="5")]
        DoubleValue(f64),
        /// string value.
        #[prost(string, tag="6")]
        StringValue(::prost::alloc::string::String),
        /// bytes value.
        #[prost(bytes, tag="7")]
        BytesValue(::prost::alloc::vec::Vec<u8>),
        /// protobuf.Duration value.
        ///
        /// Deprecated: duration is no longer considered a builtin cel type.
        #[prost(message, tag="8")]
        DurationValue(::prost_types::Duration),
        /// protobuf.Timestamp value.
        ///
        /// Deprecated: timestamp is no longer considered a builtin cel type.
        #[prost(message, tag="9")]
        TimestampValue(::prost_types::Timestamp),
    }
}
/// Source information collected at parse time.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SourceInfo {
    /// The syntax version of the source, e.g. `cel1`.
    #[prost(string, tag="1")]
    pub syntax_version: ::prost::alloc::string::String,
    /// The location name. All position information attached to an expression is
    /// relative to this location.
    ///
    /// The location could be a file, UI element, or similar. For example,
    /// `acme/app/AnvilPolicy.cel`.
    #[prost(string, tag="2")]
    pub location: ::prost::alloc::string::String,
    /// Monotonically increasing list of code point offsets where newlines
    /// `\n` appear.
    ///
    /// The line number of a given position is the index `i` where for a given
    /// `id` the `line_offsets\[i\] < id_positions\[id\] < line_offsets\[i+1\]`. The
    /// column may be derivd from `id_positions\[id\] - line_offsets\[i\]`.
    #[prost(int32, repeated, tag="3")]
    pub line_offsets: ::prost::alloc::vec::Vec<i32>,
    /// A map from the parse node id (e.g. `Expr.id`) to the code point offset
    /// within the source.
    #[prost(map="int64, int32", tag="4")]
    pub positions: ::std::collections::HashMap<i64, i32>,
    /// A map from the parse node id where a macro replacement was made to the
    /// call `Expr` that resulted in a macro expansion.
    ///
    /// For example, `has(value.field)` is a function call that is replaced by a
    /// `test_only` field selection in the AST. Likewise, the call
    /// `list.exists(e, e > 10)` translates to a comprehension expression. The key
    /// in the map corresponds to the expression id of the expanded macro, and the
    /// value is the call `Expr` that was replaced.
    #[prost(map="int64, message", tag="5")]
    pub macro_calls: ::std::collections::HashMap<i64, Expr>,
}
/// A specific position in source.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SourcePosition {
    /// The soucre location name (e.g. file name).
    #[prost(string, tag="1")]
    pub location: ::prost::alloc::string::String,
    /// The UTF-8 code unit offset.
    #[prost(int32, tag="2")]
    pub offset: i32,
    /// The 1-based index of the starting line in the source text
    /// where the issue occurs, or 0 if unknown.
    #[prost(int32, tag="3")]
    pub line: i32,
    /// The 0-based index of the starting position within the line of source text
    /// where the issue occurs.  Only meaningful if line is nonzero.
    #[prost(int32, tag="4")]
    pub column: i32,
}
// Protos for representing CEL declarations and typed checked expressions.

/// A CEL expression which has been successfully type checked.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckedExpr {
    /// A map from expression ids to resolved references.
    ///
    /// The following entries are in this table:
    ///
    /// - An Ident or Select expression is represented here if it resolves to a
    ///   declaration. For instance, if `a.b.c` is represented by
    ///   `select(select(id(a), b), c)`, and `a.b` resolves to a declaration,
    ///   while `c` is a field selection, then the reference is attached to the
    ///   nested select expression (but not to the id or or the outer select).
    ///   In turn, if `a` resolves to a declaration and `b.c` are field selections,
    ///   the reference is attached to the ident expression.
    /// - Every Call expression has an entry here, identifying the function being
    ///   called.
    /// - Every CreateStruct expression for a message has an entry, identifying
    ///   the message.
    #[prost(map="int64, message", tag="2")]
    pub reference_map: ::std::collections::HashMap<i64, Reference>,
    /// A map from expression ids to types.
    ///
    /// Every expression node which has a type different than DYN has a mapping
    /// here. If an expression has type DYN, it is omitted from this map to save
    /// space.
    #[prost(map="int64, message", tag="3")]
    pub type_map: ::std::collections::HashMap<i64, Type>,
    /// The source info derived from input that generated the parsed `expr` and
    /// any optimizations made during the type-checking pass.
    #[prost(message, optional, tag="5")]
    pub source_info: ::core::option::Option<SourceInfo>,
    /// The expr version indicates the major / minor version number of the `expr`
    /// representation.
    ///
    /// The most common reason for a version change will be to indicate to the CEL
    /// runtimes that transformations have been performed on the expr during static
    /// analysis. In some cases, this will save the runtime the work of applying
    /// the same or similar transformations prior to evaluation.
    #[prost(string, tag="6")]
    pub expr_version: ::prost::alloc::string::String,
    /// The checked expression. Semantically equivalent to the parsed `expr`, but
    /// may have structural differences.
    #[prost(message, optional, tag="4")]
    pub expr: ::core::option::Option<Expr>,
}
/// Represents a CEL type.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Type {
    /// The kind of type.
    #[prost(oneof="r#type::TypeKind", tags="1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14")]
    pub type_kind: ::core::option::Option<r#type::TypeKind>,
}
/// Nested message and enum types in `Type`.
pub mod r#type {
    /// List type with typed elements, e.g. `list<example.proto.MyMessage>`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ListType {
        /// The element type.
        #[prost(message, optional, boxed, tag="1")]
        pub elem_type: ::core::option::Option<::prost::alloc::boxed::Box<super::Type>>,
    }
    /// Map type with parameterized key and value types, e.g. `map<string, int>`.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MapType {
        /// The type of the key.
        #[prost(message, optional, boxed, tag="1")]
        pub key_type: ::core::option::Option<::prost::alloc::boxed::Box<super::Type>>,
        /// The type of the value.
        #[prost(message, optional, boxed, tag="2")]
        pub value_type: ::core::option::Option<::prost::alloc::boxed::Box<super::Type>>,
    }
    /// Function type with result and arg types.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FunctionType {
        /// Result type of the function.
        #[prost(message, optional, boxed, tag="1")]
        pub result_type: ::core::option::Option<::prost::alloc::boxed::Box<super::Type>>,
        /// Argument types of the function.
        #[prost(message, repeated, tag="2")]
        pub arg_types: ::prost::alloc::vec::Vec<super::Type>,
    }
    /// Application defined abstract type.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AbstractType {
        /// The fully qualified name of this abstract type.
        #[prost(string, tag="1")]
        pub name: ::prost::alloc::string::String,
        /// Parameter types for this abstract type.
        #[prost(message, repeated, tag="2")]
        pub parameter_types: ::prost::alloc::vec::Vec<super::Type>,
    }
    /// CEL primitive types.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum PrimitiveType {
        /// Unspecified type.
        Unspecified = 0,
        /// Boolean type.
        Bool = 1,
        /// Int64 type.
        ///
        /// Proto-based integer values are widened to int64.
        Int64 = 2,
        /// Uint64 type.
        ///
        /// Proto-based unsigned integer values are widened to uint64.
        Uint64 = 3,
        /// Double type.
        ///
        /// Proto-based float values are widened to double values.
        Double = 4,
        /// String type.
        String = 5,
        /// Bytes type.
        Bytes = 6,
    }
    /// Well-known protobuf types treated with first-class support in CEL.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum WellKnownType {
        /// Unspecified type.
        Unspecified = 0,
        /// Well-known protobuf.Any type.
        ///
        /// Any types are a polymorphic message type. During type-checking they are
        /// treated like `DYN` types, but at runtime they are resolved to a specific
        /// message type specified at evaluation time.
        Any = 1,
        /// Well-known protobuf.Timestamp type, internally referenced as `timestamp`.
        Timestamp = 2,
        /// Well-known protobuf.Duration type, internally referenced as `duration`.
        Duration = 3,
    }
    /// The kind of type.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TypeKind {
        /// Dynamic type.
        #[prost(message, tag="1")]
        Dyn(()),
        /// Null value.
        #[prost(enumeration="::prost_types::NullValue", tag="2")]
        Null(i32),
        /// Primitive types: `true`, `1u`, `-2.0`, `'string'`, `b'bytes'`.
        #[prost(enumeration="PrimitiveType", tag="3")]
        Primitive(i32),
        /// Wrapper of a primitive type, e.g. `google.protobuf.Int64Value`.
        #[prost(enumeration="PrimitiveType", tag="4")]
        Wrapper(i32),
        /// Well-known protobuf type such as `google.protobuf.Timestamp`.
        #[prost(enumeration="WellKnownType", tag="5")]
        WellKnown(i32),
        /// Parameterized list with elements of `list_type`, e.g. `list<timestamp>`.
        #[prost(message, tag="6")]
        ListType(::prost::alloc::boxed::Box<ListType>),
        /// Parameterized map with typed keys and values.
        #[prost(message, tag="7")]
        MapType(::prost::alloc::boxed::Box<MapType>),
        /// Function type.
        #[prost(message, tag="8")]
        Function(::prost::alloc::boxed::Box<FunctionType>),
        /// Protocol buffer message type.
        ///
        /// The `message_type` string specifies the qualified message type name. For
        /// example, `google.plus.Profile`.
        #[prost(string, tag="9")]
        MessageType(::prost::alloc::string::String),
        /// Type param type.
        ///
        /// The `type_param` string specifies the type parameter name, e.g. `list<E>`
        /// would be a `list_type` whose element type was a `type_param` type
        /// named `E`.
        #[prost(string, tag="10")]
        TypeParam(::prost::alloc::string::String),
        /// Type type.
        ///
        /// The `type` value specifies the target type. e.g. int is type with a
        /// target type of `Primitive.INT`.
        #[prost(message, tag="11")]
        Type(::prost::alloc::boxed::Box<super::Type>),
        /// Error type.
        ///
        /// During type-checking if an expression is an error, its type is propagated
        /// as the `ERROR` type. This permits the type-checker to discover other
        /// errors present in the expression.
        #[prost(message, tag="12")]
        Error(()),
        /// Abstract, application defined type.
        #[prost(message, tag="14")]
        AbstractType(AbstractType),
    }
}
/// Represents a declaration of a named value or function.
///
/// A declaration is part of the contract between the expression, the agent
/// evaluating that expression, and the caller requesting evaluation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Decl {
    /// The fully qualified name of the declaration.
    ///
    /// Declarations are organized in containers and this represents the full path
    /// to the declaration in its container, as in `google.api.expr.Decl`.
    ///
    /// Declarations used as \[FunctionDecl.Overload][google.api.expr.v1alpha1.Decl.FunctionDecl.Overload\] parameters may or may not
    /// have a name depending on whether the overload is function declaration or a
    /// function definition containing a result \[Expr][google.api.expr.v1alpha1.Expr\].
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Required. The declaration kind.
    #[prost(oneof="decl::DeclKind", tags="2, 3")]
    pub decl_kind: ::core::option::Option<decl::DeclKind>,
}
/// Nested message and enum types in `Decl`.
pub mod decl {
    /// Identifier declaration which specifies its type and optional `Expr` value.
    ///
    /// An identifier without a value is a declaration that must be provided at
    /// evaluation time. An identifier with a value should resolve to a constant,
    /// but may be used in conjunction with other identifiers bound at evaluation
    /// time.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IdentDecl {
        /// Required. The type of the identifier.
        #[prost(message, optional, tag="1")]
        pub r#type: ::core::option::Option<super::Type>,
        /// The constant value of the identifier. If not specified, the identifier
        /// must be supplied at evaluation time.
        #[prost(message, optional, tag="2")]
        pub value: ::core::option::Option<super::Constant>,
        /// Documentation string for the identifier.
        #[prost(string, tag="3")]
        pub doc: ::prost::alloc::string::String,
    }
    /// Function declaration specifies one or more overloads which indicate the
    /// function's parameter types and return type.
    ///
    /// Functions have no observable side-effects (there may be side-effects like
    /// logging which are not observable from CEL).
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FunctionDecl {
        /// Required. List of function overloads, must contain at least one overload.
        #[prost(message, repeated, tag="1")]
        pub overloads: ::prost::alloc::vec::Vec<function_decl::Overload>,
    }
    /// Nested message and enum types in `FunctionDecl`.
    pub mod function_decl {
        /// An overload indicates a function's parameter types and return type, and
        /// may optionally include a function body described in terms of \[Expr][google.api.expr.v1alpha1.Expr\]
        /// values.
        ///
        /// Functions overloads are declared in either a function or method
        /// call-style. For methods, the `params\[0\]` is the expected type of the
        /// target receiver.
        ///
        /// Overloads must have non-overlapping argument types after erasure of all
        /// parameterized type variables (similar as type erasure in Java).
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Overload {
            /// Required. Globally unique overload name of the function which reflects
            /// the function name and argument types.
            ///
            /// This will be used by a \[Reference][google.api.expr.v1alpha1.Reference\] to indicate the `overload_id` that
            /// was resolved for the function `name`.
            #[prost(string, tag="1")]
            pub overload_id: ::prost::alloc::string::String,
            /// List of function parameter \[Type][google.api.expr.v1alpha1.Type\] values.
            ///
            /// Param types are disjoint after generic type parameters have been
            /// replaced with the type `DYN`. Since the `DYN` type is compatible with
            /// any other type, this means that if `A` is a type parameter, the
            /// function types `int<A>` and `int<int>` are not disjoint. Likewise,
            /// `map<string, string>` is not disjoint from `map<K, V>`.
            ///
            /// When the `result_type` of a function is a generic type param, the
            /// type param name also appears as the `type` of on at least one params.
            #[prost(message, repeated, tag="2")]
            pub params: ::prost::alloc::vec::Vec<super::super::Type>,
            /// The type param names associated with the function declaration.
            ///
            /// For example, `function ex<K,V>(K key, map<K, V> map) : V` would yield
            /// the type params of `K, V`.
            #[prost(string, repeated, tag="3")]
            pub type_params: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
            /// Required. The result type of the function. For example, the operator
            /// `string.isEmpty()` would have `result_type` of `kind: BOOL`.
            #[prost(message, optional, tag="4")]
            pub result_type: ::core::option::Option<super::super::Type>,
            /// Whether the function is to be used in a method call-style `x.f(...)`
            /// or a function call-style `f(x, ...)`.
            ///
            /// For methods, the first parameter declaration, `params\[0\]` is the
            /// expected type of the target receiver.
            #[prost(bool, tag="5")]
            pub is_instance_function: bool,
            /// Documentation string for the overload.
            #[prost(string, tag="6")]
            pub doc: ::prost::alloc::string::String,
        }
    }
    /// Required. The declaration kind.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum DeclKind {
        /// Identifier declaration.
        #[prost(message, tag="2")]
        Ident(IdentDecl),
        /// Function declaration.
        #[prost(message, tag="3")]
        Function(FunctionDecl),
    }
}
/// Describes a resolved reference to a declaration.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reference {
    /// The fully qualified name of the declaration.
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// For references to functions, this is a list of `Overload.overload_id`
    /// values which match according to typing rules.
    ///
    /// If the list has more than one element, overload resolution among the
    /// presented candidates must happen at runtime because of dynamic types. The
    /// type checker attempts to narrow down this list as much as possible.
    ///
    /// Empty if this is not a reference to a \[Decl.FunctionDecl][google.api.expr.v1alpha1.Decl.FunctionDecl\].
    #[prost(string, repeated, tag="3")]
    pub overload_id: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// For references to constants, this may contain the value of the
    /// constant if known at compile time.
    #[prost(message, optional, tag="4")]
    pub value: ::core::option::Option<Constant>,
}
// Contains representations for CEL runtime values.

/// Represents a CEL value.
///
/// This is similar to `google.protobuf.Value`, but can represent CEL's full
/// range of values.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Value {
    /// Required. The valid kinds of values.
    #[prost(oneof="value::Kind", tags="1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 15")]
    pub kind: ::core::option::Option<value::Kind>,
}
/// Nested message and enum types in `Value`.
pub mod value {
    /// Required. The valid kinds of values.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Null value.
        #[prost(enumeration="::prost_types::NullValue", tag="1")]
        NullValue(i32),
        /// Boolean value.
        #[prost(bool, tag="2")]
        BoolValue(bool),
        /// Signed integer value.
        #[prost(int64, tag="3")]
        Int64Value(i64),
        /// Unsigned integer value.
        #[prost(uint64, tag="4")]
        Uint64Value(u64),
        /// Floating point value.
        #[prost(double, tag="5")]
        DoubleValue(f64),
        /// UTF-8 string value.
        #[prost(string, tag="6")]
        StringValue(::prost::alloc::string::String),
        /// Byte string value.
        #[prost(bytes, tag="7")]
        BytesValue(::prost::alloc::vec::Vec<u8>),
        /// An enum value.
        #[prost(message, tag="9")]
        EnumValue(super::EnumValue),
        /// The proto message backing an object value.
        #[prost(message, tag="10")]
        ObjectValue(::prost_types::Any),
        /// Map value.
        #[prost(message, tag="11")]
        MapValue(super::MapValue),
        /// List value.
        #[prost(message, tag="12")]
        ListValue(super::ListValue),
        /// Type value.
        #[prost(string, tag="15")]
        TypeValue(::prost::alloc::string::String),
    }
}
/// An enum value.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnumValue {
    /// The fully qualified name of the enum type.
    #[prost(string, tag="1")]
    pub r#type: ::prost::alloc::string::String,
    /// The value of the enum.
    #[prost(int32, tag="2")]
    pub value: i32,
}
/// A list.
///
/// Wrapped in a message so 'not set' and empty can be differentiated, which is
/// required for use in a 'oneof'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListValue {
    /// The ordered values in the list.
    #[prost(message, repeated, tag="1")]
    pub values: ::prost::alloc::vec::Vec<Value>,
}
/// A map.
///
/// Wrapped in a message so 'not set' and empty can be differentiated, which is
/// required for use in a 'oneof'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MapValue {
    /// The set of map entries.
    ///
    /// CEL has fewer restrictions on keys, so a protobuf map represenation
    /// cannot be used.
    #[prost(message, repeated, tag="1")]
    pub entries: ::prost::alloc::vec::Vec<map_value::Entry>,
}
/// Nested message and enum types in `MapValue`.
pub mod map_value {
    /// An entry in the map.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Entry {
        /// The key.
        ///
        /// Must be unique with in the map.
        /// Currently only boolean, int, uint, and string values can be keys.
        #[prost(message, optional, tag="1")]
        pub key: ::core::option::Option<super::Value>,
        /// The value.
        #[prost(message, optional, tag="2")]
        pub value: ::core::option::Option<super::Value>,
    }
}
/// The state of an evaluation.
///
/// Can represent an inital, partial, or completed state of evaluation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EvalState {
    /// The unique values referenced in this message.
    #[prost(message, repeated, tag="1")]
    pub values: ::prost::alloc::vec::Vec<ExprValue>,
    /// An ordered list of results.
    ///
    /// Tracks the flow of evaluation through the expression.
    /// May be sparse.
    #[prost(message, repeated, tag="3")]
    pub results: ::prost::alloc::vec::Vec<eval_state::Result>,
}
/// Nested message and enum types in `EvalState`.
pub mod eval_state {
    /// A single evalution result.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Result {
        /// The id of the expression this result if for.
        #[prost(int64, tag="1")]
        pub expr: i64,
        /// The index in `values` of the resulting value.
        #[prost(int64, tag="2")]
        pub value: i64,
    }
}
/// The value of an evaluated expression.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExprValue {
    /// An expression can resolve to a value, error or unknown.
    #[prost(oneof="expr_value::Kind", tags="1, 2, 3")]
    pub kind: ::core::option::Option<expr_value::Kind>,
}
/// Nested message and enum types in `ExprValue`.
pub mod expr_value {
    /// An expression can resolve to a value, error or unknown.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// A concrete value.
        #[prost(message, tag="1")]
        Value(super::Value),
        /// The set of errors in the critical path of evalution.
        ///
        /// Only errors in the critical path are included. For example,
        /// `(<error1> || true) && <error2>` will only result in `<error2>`,
        /// while `<error1> || <error2>` will result in both `<error1>` and
        /// `<error2>`.
        ///
        /// Errors cause by the presence of other errors are not included in the
        /// set. For example `<error1>.foo`, `foo(<error1>)`, and `<error1> + 1` will
        /// only result in `<error1>`.
        ///
        /// Multiple errors *might* be included when evaluation could result
        /// in different errors. For example `<error1> + <error2>` and
        /// `foo(<error1>, <error2>)` may result in `<error1>`, `<error2>` or both.
        /// The exact subset of errors included for this case is unspecified and
        /// depends on the implementation details of the evaluator.
        #[prost(message, tag="2")]
        Error(super::ErrorSet),
        /// The set of unknowns in the critical path of evaluation.
        ///
        /// Unknown behaves identically to Error with regards to propagation.
        /// Specifically, only unknowns in the critical path are included, unknowns
        /// caused by the presence of other unknowns are not included, and multiple
        /// unknowns *might* be included included when evaluation could result in
        /// different unknowns. For example:
        ///
        ///     (<unknown\[1\]> || true) && <unknown\[2\]> -> <unknown\[2\]>
        ///     <unknown\[1\]> || <unknown\[2\]> -> <unknown\[1,2\]>
        ///     <unknown\[1\]>.foo -> <unknown\[1\]>
        ///     foo(<unknown\[1\]>) -> <unknown\[1\]>
        ///     <unknown\[1\]> + <unknown\[2\]> -> <unknown\[1\]> or <unknown[2[>
        ///
        /// Unknown takes precidence over Error in cases where a `Value` can short
        /// circuit the result:
        ///
        ///     <error> || <unknown> -> <unknown>
        ///     <error> && <unknown> -> <unknown>
        ///
        /// Errors take precidence in all other cases:
        ///
        ///     <unknown> + <error> -> <error>
        ///     foo(<unknown>, <error>) -> <error>
        #[prost(message, tag="3")]
        Unknown(super::UnknownSet),
    }
}
/// A set of errors.
///
/// The errors included depend on the context. See `ExprValue.error`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorSet {
    /// The errors in the set.
    #[prost(message, repeated, tag="1")]
    pub errors: ::prost::alloc::vec::Vec<super::super::super::rpc::Status>,
}
/// A set of expressions for which the value is unknown.
///
/// The unknowns included depend on the context. See `ExprValue.unknown`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnknownSet {
    /// The ids of the expressions with unknown values.
    #[prost(int64, repeated, tag="1")]
    pub exprs: ::prost::alloc::vec::Vec<i64>,
}
/// Values of intermediate expressions produced when evaluating expression.
/// Deprecated, use `EvalState` instead.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Explain {
    /// All of the observed values.
    ///
    /// The field value_index is an index in the values list.
    /// Separating values from steps is needed to remove redundant values.
    #[prost(message, repeated, tag="1")]
    pub values: ::prost::alloc::vec::Vec<Value>,
    /// List of steps.
    ///
    /// Repeated evaluations of the same expression generate new ExprStep
    /// instances. The order of such ExprStep instances matches the order of
    /// elements returned by Comprehension.iter_range.
    #[prost(message, repeated, tag="2")]
    pub expr_steps: ::prost::alloc::vec::Vec<explain::ExprStep>,
}
/// Nested message and enum types in `Explain`.
pub mod explain {
    /// ID and value index of one step.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ExprStep {
        /// ID of corresponding Expr node.
        #[prost(int64, tag="1")]
        pub id: i64,
        /// Index of the value in the values list.
        #[prost(int32, tag="2")]
        pub value_index: i32,
    }
}
