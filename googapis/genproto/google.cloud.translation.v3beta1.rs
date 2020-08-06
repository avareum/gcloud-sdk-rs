/// Configures which glossary should be used for a specific target language,
/// and defines options for applying that glossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranslateTextGlossaryConfig {
    /// Required. Specifies the glossary used for this translation. Use
    /// this format: projects/*/locations/*/glossaries/*
    #[prost(string, tag = "1")]
    pub glossary: std::string::String,
    /// Optional. Indicates match is case-insensitive.
    /// Default value is false if missing.
    #[prost(bool, tag = "2")]
    pub ignore_case: bool,
}
/// The request message for synchronous translation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranslateTextRequest {
    /// Required. The content of the input in string format.
    /// We recommend the total content be less than 30k codepoints.
    /// Use BatchTranslateText for larger text.
    #[prost(string, repeated, tag = "1")]
    pub contents: ::std::vec::Vec<std::string::String>,
    /// Optional. The format of the source text, for example, "text/html",
    ///  "text/plain". If left blank, the MIME type defaults to "text/html".
    #[prost(string, tag = "3")]
    pub mime_type: std::string::String,
    /// Optional. The BCP-47 language code of the input text if
    /// known, for example, "en-US" or "sr-Latn". Supported language codes are
    /// listed in Language Support. If the source language isn't specified, the API
    /// attempts to identify the source language automatically and returns the
    /// source language within the response.
    #[prost(string, tag = "4")]
    pub source_language_code: std::string::String,
    /// Required. The BCP-47 language code to use for translation of the input
    /// text, set to one of the language codes listed in Language Support.
    #[prost(string, tag = "5")]
    pub target_language_code: std::string::String,
    /// Required. Project or location to make a call. Must refer to a caller's
    /// project.
    ///
    /// Format: `projects/{project-id}` or
    /// `projects/{project-id}/locations/{location-id}`.
    ///
    /// For global calls, use `projects/{project-id}/locations/global` or
    /// `projects/{project-id}`.
    ///
    /// Non-global location is required for requests using AutoML models or
    /// custom glossaries.
    ///
    /// Models and glossaries must be within the same region (have same
    /// location-id), otherwise an INVALID_ARGUMENT (400) error is returned.
    #[prost(string, tag = "8")]
    pub parent: std::string::String,
    /// Optional. The `model` type requested for this translation.
    ///
    /// The format depends on model type:
    ///
    /// - AutoML Translation models:
    ///   `projects/{project-id}/locations/{location-id}/models/{model-id}`
    ///
    /// - General (built-in) models:
    ///   `projects/{project-id}/locations/{location-id}/models/general/nmt`,
    ///   `projects/{project-id}/locations/{location-id}/models/general/base`
    ///
    ///
    /// For global (non-regionalized) requests, use `location-id` `global`.
    /// For example,
    /// `projects/{project-id}/locations/global/models/general/nmt`.
    ///
    /// If missing, the system decides which google base model to use.
    #[prost(string, tag = "6")]
    pub model: std::string::String,
    /// Optional. Glossary to be applied. The glossary must be
    /// within the same region (have the same location-id) as the model, otherwise
    /// an INVALID_ARGUMENT (400) error is returned.
    #[prost(message, optional, tag = "7")]
    pub glossary_config: ::std::option::Option<TranslateTextGlossaryConfig>,
    /// Optional. The labels with user-defined metadata for the request.
    ///
    /// Label keys and values can be no longer than 63 characters
    /// (Unicode codepoints), can only contain lowercase letters, numeric
    /// characters, underscores and dashes. International characters are allowed.
    /// Label values are optional. Label keys must start with a letter.
    ///
    /// See https://cloud.google.com/translate/docs/labels for more information.
    #[prost(map = "string, string", tag = "10")]
    pub labels: ::std::collections::HashMap<std::string::String, std::string::String>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TranslateTextResponse {
    /// Text translation responses with no glossary applied.
    /// This field has the same length as
    /// [`contents`][google.cloud.translation.v3beta1.TranslateTextRequest.contents].
    #[prost(message, repeated, tag = "1")]
    pub translations: ::std::vec::Vec<Translation>,
    /// Text translation responses if a glossary is provided in the request.
    /// This can be the same as
    /// [`translations`][google.cloud.translation.v3beta1.TranslateTextResponse.translations] if no terms apply.
    /// This field has the same length as
    /// [`contents`][google.cloud.translation.v3beta1.TranslateTextRequest.contents].
    #[prost(message, repeated, tag = "3")]
    pub glossary_translations: ::std::vec::Vec<Translation>,
}
/// A single translation response.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Translation {
    /// Text translated into the target language.
    #[prost(string, tag = "1")]
    pub translated_text: std::string::String,
    /// Only present when `model` is present in the request.
    /// This is same as `model` provided in the request.
    #[prost(string, tag = "2")]
    pub model: std::string::String,
    /// The BCP-47 language code of source text in the initial request, detected
    /// automatically, if no source language was passed within the initial
    /// request. If the source language was passed, auto-detection of the language
    /// does not occur and this field is empty.
    #[prost(string, tag = "4")]
    pub detected_language_code: std::string::String,
    /// The `glossary_config` used for this translation.
    #[prost(message, optional, tag = "3")]
    pub glossary_config: ::std::option::Option<TranslateTextGlossaryConfig>,
}
/// The request message for language detection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DetectLanguageRequest {
    /// Required. Project or location to make a call. Must refer to a caller's
    /// project.
    ///
    /// Format: `projects/{project-id}/locations/{location-id}` or
    /// `projects/{project-id}`.
    ///
    /// For global calls, use `projects/{project-id}/locations/global` or
    /// `projects/{project-id}`.
    ///
    /// Only models within the same region (has same location-id) can be used.
    /// Otherwise an INVALID_ARGUMENT (400) error is returned.
    #[prost(string, tag = "5")]
    pub parent: std::string::String,
    /// Optional. The language detection model to be used.
    ///
    /// Format:
    /// `projects/{project-id}/locations/{location-id}/models/language-detection/{model-id}`
    ///
    /// Only one language detection model is currently supported:
    /// `projects/{project-id}/locations/{location-id}/models/language-detection/default`.
    ///
    /// If not specified, the default model is used.
    #[prost(string, tag = "4")]
    pub model: std::string::String,
    /// Optional. The format of the source text, for example, "text/html",
    /// "text/plain". If left blank, the MIME type defaults to "text/html".
    #[prost(string, tag = "3")]
    pub mime_type: std::string::String,
    /// Optional. The labels with user-defined metadata for the request.
    ///
    /// Label keys and values can be no longer than 63 characters
    /// (Unicode codepoints), can only contain lowercase letters, numeric
    /// characters, underscores and dashes. International characters are allowed.
    /// Label values are optional. Label keys must start with a letter.
    ///
    /// See https://cloud.google.com/translate/docs/labels for more information.
    #[prost(map = "string, string", tag = "6")]
    pub labels: ::std::collections::HashMap<std::string::String, std::string::String>,
    /// Required. The source of the document from which to detect the language.
    #[prost(oneof = "detect_language_request::Source", tags = "1")]
    pub source: ::std::option::Option<detect_language_request::Source>,
}
pub mod detect_language_request {
    /// Required. The source of the document from which to detect the language.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Source {
        /// The content of the input stored as a string.
        #[prost(string, tag = "1")]
        Content(std::string::String),
    }
}
/// The response message for language detection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DetectedLanguage {
    /// The BCP-47 language code of source content in the request, detected
    /// automatically.
    #[prost(string, tag = "1")]
    pub language_code: std::string::String,
    /// The confidence of the detection result for this language.
    #[prost(float, tag = "2")]
    pub confidence: f32,
}
/// The response message for language detection.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DetectLanguageResponse {
    /// A list of detected languages sorted by detection confidence in descending
    /// order. The most probable language first.
    #[prost(message, repeated, tag = "1")]
    pub languages: ::std::vec::Vec<DetectedLanguage>,
}
/// The request message for discovering supported languages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSupportedLanguagesRequest {
    /// Required. Project or location to make a call. Must refer to a caller's
    /// project.
    ///
    /// Format: `projects/{project-id}` or
    /// `projects/{project-id}/locations/{location-id}`.
    ///
    /// For global calls, use `projects/{project-id}/locations/global` or
    /// `projects/{project-id}`.
    ///
    /// Non-global location is required for AutoML models.
    ///
    /// Only models within the same region (have same location-id) can be used,
    /// otherwise an INVALID_ARGUMENT (400) error is returned.
    #[prost(string, tag = "3")]
    pub parent: std::string::String,
    /// Optional. The language to use to return localized, human readable names
    /// of supported languages. If missing, then display names are not returned
    /// in a response.
    #[prost(string, tag = "1")]
    pub display_language_code: std::string::String,
    /// Optional. Get supported languages of this model.
    ///
    /// The format depends on model type:
    ///
    /// - AutoML Translation models:
    ///   `projects/{project-id}/locations/{location-id}/models/{model-id}`
    ///
    /// - General (built-in) models:
    ///   `projects/{project-id}/locations/{location-id}/models/general/nmt`,
    ///   `projects/{project-id}/locations/{location-id}/models/general/base`
    ///
    ///
    /// Returns languages supported by the specified model.
    /// If missing, we get supported languages of Google general base (PBMT) model.
    #[prost(string, tag = "2")]
    pub model: std::string::String,
}
/// The response message for discovering supported languages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SupportedLanguages {
    /// A list of supported language responses. This list contains an entry
    /// for each language the Translation API supports.
    #[prost(message, repeated, tag = "1")]
    pub languages: ::std::vec::Vec<SupportedLanguage>,
}
/// A single supported language response corresponds to information related
/// to one supported language.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SupportedLanguage {
    /// Supported language code, generally consisting of its ISO 639-1
    /// identifier, for example, 'en', 'ja'. In certain cases, BCP-47 codes
    /// including language and region identifiers are returned (for example,
    /// 'zh-TW' and 'zh-CN')
    #[prost(string, tag = "1")]
    pub language_code: std::string::String,
    /// Human readable name of the language localized in the display language
    /// specified in the request.
    #[prost(string, tag = "2")]
    pub display_name: std::string::String,
    /// Can be used as source language.
    #[prost(bool, tag = "3")]
    pub support_source: bool,
    /// Can be used as target language.
    #[prost(bool, tag = "4")]
    pub support_target: bool,
}
/// The Google Cloud Storage location for the input content.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GcsSource {
    /// Required. Source data URI. For example, `gs://my_bucket/my_object`.
    #[prost(string, tag = "1")]
    pub input_uri: std::string::String,
}
/// Input configuration for BatchTranslateText request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InputConfig {
    /// Optional. Can be "text/plain" or "text/html".
    /// For `.tsv`, "text/html" is used if mime_type is missing.
    /// For `.html`, this field must be "text/html" or empty.
    /// For `.txt`, this field must be "text/plain" or empty.
    #[prost(string, tag = "1")]
    pub mime_type: std::string::String,
    /// Required. Specify the input.
    #[prost(oneof = "input_config::Source", tags = "2")]
    pub source: ::std::option::Option<input_config::Source>,
}
pub mod input_config {
    /// Required. Specify the input.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Source {
        /// Required. Google Cloud Storage location for the source input.
        /// This can be a single file (for example,
        /// `gs://translation-test/input.tsv`) or a wildcard (for example,
        /// `gs://translation-test/*`). If a file extension is `.tsv`, it can
        /// contain either one or two columns. The first column (optional) is the id
        /// of the text request. If the first column is missing, we use the row
        /// number (0-based) from the input file as the ID in the output file. The
        /// second column is the actual text to be
        ///  translated. We recommend each row be <= 10K Unicode codepoints,
        /// otherwise an error might be returned.
        /// Note that the input tsv must be RFC 4180 compliant.
        ///
        /// You could use https://github.com/Clever/csvlint to check potential
        /// formatting errors in your tsv file.
        /// csvlint --delimiter='\t' your_input_file.tsv
        ///
        /// The other supported file extensions are `.txt` or `.html`, which is
        /// treated as a single large chunk of text.
        #[prost(message, tag = "2")]
        GcsSource(super::GcsSource),
    }
}
/// The Google Cloud Storage location for the output content.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GcsDestination {
    /// Required. There must be no files under 'output_uri_prefix'.
    /// 'output_uri_prefix' must end with "/" and start with "gs://", otherwise an
    /// INVALID_ARGUMENT (400) error is returned.
    #[prost(string, tag = "1")]
    pub output_uri_prefix: std::string::String,
}
/// Output configuration for BatchTranslateText request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutputConfig {
    /// Required. The destination of output.
    #[prost(oneof = "output_config::Destination", tags = "1")]
    pub destination: ::std::option::Option<output_config::Destination>,
}
pub mod output_config {
    /// Required. The destination of output.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Destination {
        /// Google Cloud Storage destination for output content.
        /// For every single input file (for example, gs://a/b/c.[extension]), we
        /// generate at most 2 * n output files. (n is the # of target_language_codes
        /// in the BatchTranslateTextRequest).
        ///
        /// Output files (tsv) generated are compliant with RFC 4180 except that
        /// record delimiters are '\n' instead of '\r\n'. We don't provide any way to
        /// change record delimiters.
        ///
        /// While the input files are being processed, we write/update an index file
        /// 'index.csv'  under 'output_uri_prefix' (for example,
        /// gs://translation-test/index.csv) The index file is generated/updated as
        /// new files are being translated. The format is:
        ///
        /// input_file,target_language_code,translations_file,errors_file,
        /// glossary_translations_file,glossary_errors_file
        ///
        /// input_file is one file we matched using gcs_source.input_uri.
        /// target_language_code is provided in the request.
        /// translations_file contains the translations. (details provided below)
        /// errors_file contains the errors during processing of the file. (details
        /// below). Both translations_file and errors_file could be empty
        /// strings if we have no content to output.
        /// glossary_translations_file and glossary_errors_file are always empty
        /// strings if the input_file is tsv. They could also be empty if we have no
        /// content to output.
        ///
        /// Once a row is present in index.csv, the input/output matching never
        /// changes. Callers should also expect all the content in input_file are
        /// processed and ready to be consumed (that is, no partial output file is
        /// written).
        ///
        /// The format of translations_file (for target language code 'trg') is:
        /// `gs://translation_test/a_b_c_'trg'_translations.[extension]`
        ///
        /// If the input file extension is tsv, the output has the following
        /// columns:
        /// Column 1: ID of the request provided in the input, if it's not
        /// provided in the input, then the input row number is used (0-based).
        /// Column 2: source sentence.
        /// Column 3: translation without applying a glossary. Empty string if there
        /// is an error.
        /// Column 4 (only present if a glossary is provided in the request):
        /// translation after applying the glossary. Empty string if there is an
        /// error applying the glossary. Could be same string as column 3 if there is
        /// no glossary applied.
        ///
        /// If input file extension is a txt or html, the translation is directly
        /// written to the output file. If glossary is requested, a separate
        /// glossary_translations_file has format of
        /// `gs://translation_test/a_b_c_'trg'_glossary_translations.[extension]`
        ///
        /// The format of errors file (for target language code 'trg') is:
        /// `gs://translation_test/a_b_c_'trg'_errors.[extension]`
        ///
        /// If the input file extension is tsv, errors_file contains the following:
        /// Column 1: ID of the request provided in the input, if it's not
        /// provided in the input, then the input row number is used (0-based).
        /// Column 2: source sentence.
        /// Column 3: Error detail for the translation. Could be empty.
        /// Column 4 (only present if a glossary is provided in the request):
        /// Error when applying the glossary.
        ///
        /// If the input file extension is txt or html, glossary_error_file will be
        /// generated that contains error details. glossary_error_file has format of
        /// `gs://translation_test/a_b_c_'trg'_glossary_errors.[extension]`
        #[prost(message, tag = "1")]
        GcsDestination(super::GcsDestination),
    }
}
/// The batch translation request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BatchTranslateTextRequest {
    /// Required. Location to make a call. Must refer to a caller's project.
    ///
    /// Format: `projects/{project-id}/locations/{location-id}`.
    ///
    /// The `global` location is not supported for batch translation.
    ///
    /// Only AutoML Translation models or glossaries within the same region (have
    /// the same location-id) can be used, otherwise an INVALID_ARGUMENT (400)
    /// error is returned.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Required. Source language code.
    #[prost(string, tag = "2")]
    pub source_language_code: std::string::String,
    /// Required. Specify up to 10 language codes here.
    #[prost(string, repeated, tag = "3")]
    pub target_language_codes: ::std::vec::Vec<std::string::String>,
    /// Optional. The models to use for translation. Map's key is target language
    /// code. Map's value is model name. Value can be a built-in general model,
    /// or an AutoML Translation model.
    ///
    /// The value format depends on model type:
    ///
    /// - AutoML Translation models:
    ///   `projects/{project-id}/locations/{location-id}/models/{model-id}`
    ///
    /// - General (built-in) models:
    ///   `projects/{project-id}/locations/{location-id}/models/general/nmt`,
    ///   `projects/{project-id}/locations/{location-id}/models/general/base`
    ///
    ///
    /// If the map is empty or a specific model is
    /// not requested for a language pair, then default google model (nmt) is used.
    #[prost(map = "string, string", tag = "4")]
    pub models: ::std::collections::HashMap<std::string::String, std::string::String>,
    /// Required. Input configurations.
    /// The total number of files matched should be <= 1000.
    /// The total content size should be <= 100M Unicode codepoints.
    /// The files must use UTF-8 encoding.
    #[prost(message, repeated, tag = "5")]
    pub input_configs: ::std::vec::Vec<InputConfig>,
    /// Required. Output configuration.
    /// If 2 input configs match to the same file (that is, same input path),
    /// we don't generate output for duplicate inputs.
    #[prost(message, optional, tag = "6")]
    pub output_config: ::std::option::Option<OutputConfig>,
    /// Optional. Glossaries to be applied for translation.
    /// It's keyed by target language code.
    #[prost(map = "string, message", tag = "7")]
    pub glossaries: ::std::collections::HashMap<std::string::String, TranslateTextGlossaryConfig>,
    /// Optional. The labels with user-defined metadata for the request.
    ///
    /// Label keys and values can be no longer than 63 characters
    /// (Unicode codepoints), can only contain lowercase letters, numeric
    /// characters, underscores and dashes. International characters are allowed.
    /// Label values are optional. Label keys must start with a letter.
    ///
    /// See https://cloud.google.com/translate/docs/labels for more information.
    #[prost(map = "string, string", tag = "9")]
    pub labels: ::std::collections::HashMap<std::string::String, std::string::String>,
}
/// State metadata for the batch translation operation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BatchTranslateMetadata {
    /// The state of the operation.
    #[prost(enumeration = "batch_translate_metadata::State", tag = "1")]
    pub state: i32,
    /// Number of successfully translated characters so far (Unicode codepoints).
    #[prost(int64, tag = "2")]
    pub translated_characters: i64,
    /// Number of characters that have failed to process so far (Unicode
    /// codepoints).
    #[prost(int64, tag = "3")]
    pub failed_characters: i64,
    /// Total number of characters (Unicode codepoints).
    /// This is the total number of codepoints from input files times the number of
    /// target languages and appears here shortly after the call is submitted.
    #[prost(int64, tag = "4")]
    pub total_characters: i64,
    /// Time when the operation was submitted.
    #[prost(message, optional, tag = "5")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
}
pub mod batch_translate_metadata {
    /// State of the job.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum State {
        /// Invalid.
        Unspecified = 0,
        /// Request is being processed.
        Running = 1,
        /// The batch is processed, and at least one item was successfully
        /// processed.
        Succeeded = 2,
        /// The batch is done and no item was successfully processed.
        Failed = 3,
        /// Request is in the process of being canceled after caller invoked
        /// longrunning.Operations.CancelOperation on the request id.
        Cancelling = 4,
        /// The batch is done after the user has called the
        /// longrunning.Operations.CancelOperation. Any records processed before the
        /// cancel command are output as specified in the request.
        Cancelled = 5,
    }
}
/// Stored in the [google.longrunning.Operation.response][google.longrunning.Operation.response] field returned by
/// BatchTranslateText if at least one sentence is translated successfully.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BatchTranslateResponse {
    /// Total number of characters (Unicode codepoints).
    #[prost(int64, tag = "1")]
    pub total_characters: i64,
    /// Number of successfully translated characters (Unicode codepoints).
    #[prost(int64, tag = "2")]
    pub translated_characters: i64,
    /// Number of characters that have failed to process (Unicode codepoints).
    #[prost(int64, tag = "3")]
    pub failed_characters: i64,
    /// Time when the operation was submitted.
    #[prost(message, optional, tag = "4")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
    /// The time when the operation is finished and
    /// [google.longrunning.Operation.done][google.longrunning.Operation.done] is set to true.
    #[prost(message, optional, tag = "5")]
    pub end_time: ::std::option::Option<::prost_types::Timestamp>,
}
/// Input configuration for glossaries.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GlossaryInputConfig {
    /// Required. Specify the input.
    #[prost(oneof = "glossary_input_config::Source", tags = "1")]
    pub source: ::std::option::Option<glossary_input_config::Source>,
}
pub mod glossary_input_config {
    /// Required. Specify the input.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Source {
        /// Required. Google Cloud Storage location of glossary data.
        /// File format is determined based on the filename extension. API returns
        /// [google.rpc.Code.INVALID_ARGUMENT] for unsupported URI-s and file
        /// formats. Wildcards are not allowed. This must be a single file in one of
        /// the following formats:
        ///
        /// For unidirectional glossaries:
        ///
        /// - TSV/CSV (`.tsv`/`.csv`): 2 column file, tab- or comma-separated.
        ///   The first column is source text. The second column is target text.
        ///   The file must not contain headers. That is, the first row is data, not
        ///   column names.
        ///
        /// - TMX (`.tmx`): TMX file with parallel data defining source/target term
        /// pairs.
        ///
        /// For equivalent term sets glossaries:
        ///
        /// - CSV (`.csv`): Multi-column CSV file defining equivalent glossary terms
        ///   in multiple languages. The format is defined for Google Translation
        ///   Toolkit and documented in [Use a
        ///   glossary](https://support.google.com/translatortoolkit/answer/6306379?hl=en).
        #[prost(message, tag = "1")]
        GcsSource(super::GcsSource),
    }
}
/// Represents a glossary built from user provided data.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Glossary {
    /// Required. The resource name of the glossary. Glossary names have the form
    /// `projects/{project-id}/locations/{location-id}/glossaries/{glossary-id}`.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// Required. Provides examples to build the glossary from.
    /// Total glossary must not exceed 10M Unicode codepoints.
    #[prost(message, optional, tag = "5")]
    pub input_config: ::std::option::Option<GlossaryInputConfig>,
    /// Output only. The number of entries defined in the glossary.
    #[prost(int32, tag = "6")]
    pub entry_count: i32,
    /// Output only. When CreateGlossary was called.
    #[prost(message, optional, tag = "7")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Output only. When the glossary creation was finished.
    #[prost(message, optional, tag = "8")]
    pub end_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Languages supported by the glossary.
    #[prost(oneof = "glossary::Languages", tags = "3, 4")]
    pub languages: ::std::option::Option<glossary::Languages>,
}
pub mod glossary {
    /// Used with unidirectional glossaries.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LanguageCodePair {
        /// Required. The BCP-47 language code of the input text, for example,
        /// "en-US". Expected to be an exact match for GlossaryTerm.language_code.
        #[prost(string, tag = "1")]
        pub source_language_code: std::string::String,
        /// Required. The BCP-47 language code for translation output, for example,
        /// "zh-CN". Expected to be an exact match for GlossaryTerm.language_code.
        #[prost(string, tag = "2")]
        pub target_language_code: std::string::String,
    }
    /// Used with equivalent term set glossaries.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LanguageCodesSet {
        /// The BCP-47 language code(s) for terms defined in the glossary.
        /// All entries are unique. The list contains at least two entries.
        /// Expected to be an exact match for GlossaryTerm.language_code.
        #[prost(string, repeated, tag = "1")]
        pub language_codes: ::std::vec::Vec<std::string::String>,
    }
    /// Languages supported by the glossary.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Languages {
        /// Used with unidirectional glossaries.
        #[prost(message, tag = "3")]
        LanguagePair(LanguageCodePair),
        /// Used with equivalent term set glossaries.
        #[prost(message, tag = "4")]
        LanguageCodesSet(LanguageCodesSet),
    }
}
/// Request message for CreateGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateGlossaryRequest {
    /// Required. The project name.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Required. The glossary to create.
    #[prost(message, optional, tag = "2")]
    pub glossary: ::std::option::Option<Glossary>,
}
/// Request message for GetGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetGlossaryRequest {
    /// Required. The name of the glossary to retrieve.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
}
/// Request message for DeleteGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteGlossaryRequest {
    /// Required. The name of the glossary to delete.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
}
/// Request message for ListGlossaries.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListGlossariesRequest {
    /// Required. The name of the project from which to list all of the glossaries.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Optional. Requested page size. The server may return fewer glossaries than
    /// requested. If unspecified, the server picks an appropriate default.
    #[prost(int32, tag = "2")]
    pub page_size: i32,
    /// Optional. A token identifying a page of results the server should return.
    /// Typically, this is the value of [ListGlossariesResponse.next_page_token]
    /// returned from the previous call to `ListGlossaries` method.
    /// The first page is returned if `page_token`is empty or missing.
    #[prost(string, tag = "3")]
    pub page_token: std::string::String,
    /// Optional. Filter specifying constraints of a list operation.
    /// Filtering is not supported yet, and the parameter currently has no effect.
    /// If missing, no filtering is performed.
    #[prost(string, tag = "4")]
    pub filter: std::string::String,
}
/// Response message for ListGlossaries.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListGlossariesResponse {
    /// The list of glossaries for a project.
    #[prost(message, repeated, tag = "1")]
    pub glossaries: ::std::vec::Vec<Glossary>,
    /// A token to retrieve a page of results. Pass this value in the
    /// [ListGlossariesRequest.page_token] field in the subsequent call to
    /// `ListGlossaries` method to retrieve the next page of results.
    #[prost(string, tag = "2")]
    pub next_page_token: std::string::String,
}
/// Stored in the [google.longrunning.Operation.metadata][google.longrunning.Operation.metadata] field returned by
/// CreateGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateGlossaryMetadata {
    /// The name of the glossary that is being created.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// The current state of the glossary creation operation.
    #[prost(enumeration = "create_glossary_metadata::State", tag = "2")]
    pub state: i32,
    /// The time when the operation was submitted to the server.
    #[prost(message, optional, tag = "3")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
}
pub mod create_glossary_metadata {
    /// Enumerates the possible states that the creation request can be in.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum State {
        /// Invalid.
        Unspecified = 0,
        /// Request is being processed.
        Running = 1,
        /// The glossary was successfully created.
        Succeeded = 2,
        /// Failed to create the glossary.
        Failed = 3,
        /// Request is in the process of being canceled after caller invoked
        /// longrunning.Operations.CancelOperation on the request id.
        Cancelling = 4,
        /// The glossary creation request was successfully canceled.
        Cancelled = 5,
    }
}
/// Stored in the [google.longrunning.Operation.metadata][google.longrunning.Operation.metadata] field returned by
/// DeleteGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteGlossaryMetadata {
    /// The name of the glossary that is being deleted.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// The current state of the glossary deletion operation.
    #[prost(enumeration = "delete_glossary_metadata::State", tag = "2")]
    pub state: i32,
    /// The time when the operation was submitted to the server.
    #[prost(message, optional, tag = "3")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
}
pub mod delete_glossary_metadata {
    /// Enumerates the possible states that the creation request can be in.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum State {
        /// Invalid.
        Unspecified = 0,
        /// Request is being processed.
        Running = 1,
        /// The glossary was successfully deleted.
        Succeeded = 2,
        /// Failed to delete the glossary.
        Failed = 3,
        /// Request is in the process of being canceled after caller invoked
        /// longrunning.Operations.CancelOperation on the request id.
        Cancelling = 4,
        /// The glossary deletion request was successfully canceled.
        Cancelled = 5,
    }
}
/// Stored in the [google.longrunning.Operation.response][google.longrunning.Operation.response] field returned by
/// DeleteGlossary.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteGlossaryResponse {
    /// The name of the deleted glossary.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// The time when the operation was submitted to the server.
    #[prost(message, optional, tag = "2")]
    pub submit_time: ::std::option::Option<::prost_types::Timestamp>,
    /// The time when the glossary deletion is finished and
    /// [google.longrunning.Operation.done][google.longrunning.Operation.done] is set to true.
    #[prost(message, optional, tag = "3")]
    pub end_time: ::std::option::Option<::prost_types::Timestamp>,
}
#[doc = r" Generated client implementations."]
pub mod translation_service_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    #[doc = " Provides natural language translation operations."]
    pub struct TranslationServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> TranslationServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        #[doc = " Translates input text and returns translated text."]
        pub async fn translate_text(
            &mut self,
            request: impl tonic::IntoRequest<super::TranslateTextRequest>,
        ) -> Result<tonic::Response<super::TranslateTextResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/TranslateText",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Detects the language of text within a request."]
        pub async fn detect_language(
            &mut self,
            request: impl tonic::IntoRequest<super::DetectLanguageRequest>,
        ) -> Result<tonic::Response<super::DetectLanguageResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/DetectLanguage",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Returns a list of supported languages for translation."]
        pub async fn get_supported_languages(
            &mut self,
            request: impl tonic::IntoRequest<super::GetSupportedLanguagesRequest>,
        ) -> Result<tonic::Response<super::SupportedLanguages>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/GetSupportedLanguages",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Translates a large volume of text in asynchronous batch mode."]
        #[doc = " This function provides real-time output as the inputs are being processed."]
        #[doc = " If caller cancels a request, the partial results (for an input file, it's"]
        #[doc = " all or nothing) may still be available on the specified output location."]
        #[doc = ""]
        #[doc = " This call returns immediately and you can"]
        #[doc = " use google.longrunning.Operation.name to poll the status of the call."]
        pub async fn batch_translate_text(
            &mut self,
            request: impl tonic::IntoRequest<super::BatchTranslateTextRequest>,
        ) -> Result<
            tonic::Response<super::super::super::super::longrunning::Operation>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/BatchTranslateText",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Creates a glossary and returns the long-running operation. Returns"]
        #[doc = " NOT_FOUND, if the project doesn't exist."]
        pub async fn create_glossary(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateGlossaryRequest>,
        ) -> Result<
            tonic::Response<super::super::super::super::longrunning::Operation>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/CreateGlossary",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Lists glossaries in a project. Returns NOT_FOUND, if the project doesn't"]
        #[doc = " exist."]
        pub async fn list_glossaries(
            &mut self,
            request: impl tonic::IntoRequest<super::ListGlossariesRequest>,
        ) -> Result<tonic::Response<super::ListGlossariesResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/ListGlossaries",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Gets a glossary. Returns NOT_FOUND, if the glossary doesn't"]
        #[doc = " exist."]
        pub async fn get_glossary(
            &mut self,
            request: impl tonic::IntoRequest<super::GetGlossaryRequest>,
        ) -> Result<tonic::Response<super::Glossary>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/GetGlossary",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Deletes a glossary, or cancels glossary construction"]
        #[doc = " if the glossary isn't created yet."]
        #[doc = " Returns NOT_FOUND, if the glossary doesn't exist."]
        pub async fn delete_glossary(
            &mut self,
            request: impl tonic::IntoRequest<super::DeleteGlossaryRequest>,
        ) -> Result<
            tonic::Response<super::super::super::super::longrunning::Operation>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.cloud.translation.v3beta1.TranslationService/DeleteGlossary",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for TranslationServiceClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for TranslationServiceClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TranslationServiceClient {{ ... }}")
        }
    }
}
