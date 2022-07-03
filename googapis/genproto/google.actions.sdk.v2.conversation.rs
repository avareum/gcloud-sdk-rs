/// Represents an intent.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Intent {
    /// Required. The name of the last matched intent.
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Required. Represents parameters identified as part of intent matching.
    /// This is a map of the name of the identified parameter to the value of the
    /// parameter identified from user input. All parameters defined in
    /// the matched intent that are identified will be surfaced here.
    #[prost(map="string, message", tag="2")]
    pub params: ::std::collections::HashMap<::prost::alloc::string::String, IntentParameterValue>,
    /// Optional. Typed or spoken input from the end user that matched this intent.
    /// This will be populated when an intent is matched, based on the user input.
    #[prost(string, tag="3")]
    pub query: ::prost::alloc::string::String,
}
/// Represents a value for intent parameter.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IntentParameterValue {
    /// Required. Original text value extracted from user utterance.
    #[prost(string, tag="1")]
    pub original: ::prost::alloc::string::String,
    /// Required. Structured value for parameter extracted from user input.
    /// This will only be populated if the parameter is defined in the matched
    /// intent and the value of the parameter could be identified during intent
    /// matching.
    #[prost(message, optional, tag="2")]
    pub resolved: ::core::option::Option<::prost_types::Value>,
}
/// Represents an Interactive Canvas response to be sent to the user.
/// This can be used in conjunction with the "first_simple" field in the
/// containing prompt to speak to the user in addition to displaying a
/// interactive canvas response. The maximum size of the response is 50k bytes.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Canvas {
    /// URL of the interactive canvas web app to load. If not set, the url from
    /// current active canvas will be reused.
    #[prost(string, tag="1")]
    pub url: ::prost::alloc::string::String,
    /// Optional. JSON data to be passed through to the immersive experience
    /// web page as an event.
    /// If the "override" field in the containing prompt is "false" data values
    /// defined in this Canvas prompt will be added after data values defined in
    /// previous Canvas prompts.
    #[prost(message, repeated, tag="4")]
    pub data: ::prost::alloc::vec::Vec<::prost_types::Value>,
    /// Optional. Default value: false.
    #[prost(bool, tag="3")]
    pub suppress_mic: bool,
    /// If `true` the canvas application occupies the full screen and won't
    /// have a header at the top. A toast message will also be displayed on the
    /// loading screen that includes the Action's display name, the developer's
    /// name, and instructions for exiting the Action. Default value: `false`.
    #[prost(bool, tag="8")]
    pub enable_full_screen: bool,
}
/// An image displayed in the card.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Image {
    /// The source url of the image. Images can be JPG, PNG and GIF (animated and
    /// non-animated). For example,`<https://www.agentx.com/logo.png`.> Required.
    #[prost(string, tag="1")]
    pub url: ::prost::alloc::string::String,
    /// A text description of the image to be used for accessibility, e.g. screen
    /// readers.
    /// Required.
    #[prost(string, tag="2")]
    pub alt: ::prost::alloc::string::String,
    /// The height of the image in pixels.
    /// Optional.
    #[prost(int32, tag="3")]
    pub height: i32,
    /// The width of the image in pixels.
    /// Optional.
    #[prost(int32, tag="4")]
    pub width: i32,
}
/// Nested message and enum types in `Image`.
pub mod image {
    /// Possible image display options for affecting the presentation of the image.
    /// This should be used for when the image's aspect ratio does not match the
    /// image container's aspect ratio.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ImageFill {
        /// Unspecified image fill.
        Unspecified = 0,
        /// Fill the gaps between the image and the image container with gray bars.
        Gray = 1,
        /// Fill the gaps between the image and the image container with white bars.
        White = 2,
        /// Image is scaled such that the image width and height match or exceed the
        /// container dimensions. This may crop the top and bottom of the image if
        /// the scaled image height is greater than the container height, or crop the
        /// left and right of the image if the scaled image width is greater than the
        /// container width. This is similar to "Zoom Mode" on a widescreen TV when
        /// playing a 4:3 video.
        Cropped = 3,
    }
}
/// Link content.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Link {
    /// Name of the link
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// What happens when a user opens the link
    #[prost(message, optional, tag="2")]
    pub open: ::core::option::Option<OpenUrl>,
}
/// Action taken when a user opens a link.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OpenUrl {
    /// The url field which could be any of:
    /// - http/https urls for opening an App-linked App or a webpage
    #[prost(string, tag="1")]
    pub url: ::prost::alloc::string::String,
    /// Indicates a hint for the url type.
    #[prost(enumeration="UrlHint", tag="2")]
    pub hint: i32,
}
/// Different types of url hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum UrlHint {
    /// Unspecified
    LinkUnspecified = 0,
    /// URL that points directly to AMP content, or to a canonical URL
    /// which refers to AMP content via <link rel="amphtml">.
    Amp = 1,
}
/// A basic card for displaying some information, e.g. an image and/or text.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Card {
    /// Overall title of the card.
    /// Optional.
    #[prost(string, tag="1")]
    pub title: ::prost::alloc::string::String,
    /// Optional.
    #[prost(string, tag="2")]
    pub subtitle: ::prost::alloc::string::String,
    /// Body text of the card.
    /// Supports a limited set of markdown syntax for formatting.
    /// Required, unless image is present.
    #[prost(string, tag="3")]
    pub text: ::prost::alloc::string::String,
    /// A hero image for the card. The height is fixed to 192dp.
    /// Optional.
    #[prost(message, optional, tag="4")]
    pub image: ::core::option::Option<Image>,
    /// How the image background will be filled. Optional.
    #[prost(enumeration="image::ImageFill", tag="5")]
    pub image_fill: i32,
    /// Button.
    /// Optional.
    #[prost(message, optional, tag="6")]
    pub button: ::core::option::Option<Link>,
}
/// A card for presenting a collection of options to select from.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Collection {
    /// Title of the collection. Optional.
    #[prost(string, tag="1")]
    pub title: ::prost::alloc::string::String,
    /// Subtitle of the collection. Optional.
    #[prost(string, tag="2")]
    pub subtitle: ::prost::alloc::string::String,
    /// min: 2 max: 10
    #[prost(message, repeated, tag="3")]
    pub items: ::prost::alloc::vec::Vec<collection::CollectionItem>,
    /// How the image backgrounds of collection items will be filled. Optional.
    #[prost(enumeration="image::ImageFill", tag="4")]
    pub image_fill: i32,
}
/// Nested message and enum types in `Collection`.
pub mod collection {
    /// An item in the collection
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CollectionItem {
        /// Required. The NLU key that matches the entry key name in the associated
        /// Type.
        #[prost(string, tag="1")]
        pub key: ::prost::alloc::string::String,
    }
}
/// A card for presenting a list of options to select from.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct List {
    /// Title of the list. Optional.
    #[prost(string, tag="1")]
    pub title: ::prost::alloc::string::String,
    /// Subtitle of the list. Optional.
    #[prost(string, tag="2")]
    pub subtitle: ::prost::alloc::string::String,
    /// min: 2 max: 30
    #[prost(message, repeated, tag="3")]
    pub items: ::prost::alloc::vec::Vec<list::ListItem>,
}
/// Nested message and enum types in `List`.
pub mod list {
    /// An item in the list
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ListItem {
        /// Required. The NLU key that matches the entry key name in the associated
        /// Type.
        #[prost(string, tag="1")]
        pub key: ::prost::alloc::string::String,
    }
}
/// Represents one media object.
/// Contains information about the media, such as name, description, url, etc.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Media {
    /// Media type.
    #[prost(enumeration="media::MediaType", tag="8")]
    pub media_type: i32,
    /// Start offset of the first media object.
    #[prost(message, optional, tag="5")]
    pub start_offset: ::core::option::Option<::prost_types::Duration>,
    /// Optional media control types this media response session can support.
    /// If set, request will be made to 3p when a certain media event happens.
    /// If not set, 3p must still handle two default control type, FINISHED and
    /// FAILED.
    #[prost(enumeration="media::OptionalMediaControls", repeated, tag="6")]
    pub optional_media_controls: ::prost::alloc::vec::Vec<i32>,
    /// List of Media Objects
    #[prost(message, repeated, tag="7")]
    pub media_objects: ::prost::alloc::vec::Vec<MediaObject>,
}
/// Nested message and enum types in `Media`.
pub mod media {
    /// Media type of this response.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MediaType {
        /// Unspecified media type.
        Unspecified = 0,
        /// Audio file.
        Audio = 1,
        /// Response to acknowledge a media status report.
        MediaStatusAck = 2,
    }
    /// Optional media control types the media response can support
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum OptionalMediaControls {
        /// Unspecified value
        Unspecified = 0,
        /// Paused event. Triggered when user pauses the media.
        Paused = 1,
        /// Stopped event. Triggered when user exits out of 3p session during media
        /// play.
        Stopped = 2,
    }
}
/// Represents a single media object
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaObject {
    /// Name of this media object.
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    /// Description of this media object.
    #[prost(string, tag="2")]
    pub description: ::prost::alloc::string::String,
    /// The url pointing to the media content.
    #[prost(string, tag="3")]
    pub url: ::prost::alloc::string::String,
    /// Image to show with the media card.
    #[prost(message, optional, tag="4")]
    pub image: ::core::option::Option<MediaImage>,
}
/// Image to show with the media card.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MediaImage {
    /// Image.
    #[prost(oneof="media_image::Image", tags="1, 2")]
    pub image: ::core::option::Option<media_image::Image>,
}
/// Nested message and enum types in `MediaImage`.
pub mod media_image {
    /// Image.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Image {
        /// A large image, such as the cover of the album, etc.
        #[prost(message, tag="1")]
        Large(super::Image),
        /// A small image icon displayed on the right from the title.
        /// It's resized to 36x36 dp.
        #[prost(message, tag="2")]
        Icon(super::Image),
    }
}
/// A table card for displaying a table of text.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Table {
    /// Overall title of the table. Optional but must be set if subtitle is set.
    #[prost(string, tag="1")]
    pub title: ::prost::alloc::string::String,
    /// Subtitle for the table. Optional.
    #[prost(string, tag="2")]
    pub subtitle: ::prost::alloc::string::String,
    /// Image associated with the table. Optional.
    #[prost(message, optional, tag="4")]
    pub image: ::core::option::Option<Image>,
    /// Headers and alignment of columns.
    #[prost(message, repeated, tag="5")]
    pub columns: ::prost::alloc::vec::Vec<TableColumn>,
    /// Row data of the table. The first 3 rows are guaranteed to be shown but
    /// others might be cut on certain surfaces. Please test with the simulator to
    /// see which rows will be shown for a given surface. On surfaces that support
    /// the WEB_BROWSER capability, you can point the user to
    /// a web page with more data.
    #[prost(message, repeated, tag="6")]
    pub rows: ::prost::alloc::vec::Vec<TableRow>,
    /// Button.
    #[prost(message, optional, tag="7")]
    pub button: ::core::option::Option<Link>,
}
/// Describes a column in a table.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TableColumn {
    /// Header text for the column.
    #[prost(string, tag="1")]
    pub header: ::prost::alloc::string::String,
    /// Horizontal alignment of content w.r.t column. If unspecified, content
    /// will be aligned to the leading edge.
    #[prost(enumeration="table_column::HorizontalAlignment", tag="2")]
    pub align: i32,
}
/// Nested message and enum types in `TableColumn`.
pub mod table_column {
    /// The alignment of the content within the cell.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum HorizontalAlignment {
        /// Unspecified horizontal alignment.
        Unspecified = 0,
        /// Leading edge of the cell. This is the default.
        Leading = 1,
        /// Content is aligned to the center of the column.
        Center = 2,
        /// Content is aligned to the trailing edge of the column.
        Trailing = 3,
    }
}
/// Describes a cell in a row.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TableCell {
    /// Text content of the cell.
    #[prost(string, tag="1")]
    pub text: ::prost::alloc::string::String,
}
/// Describes a row in the table.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TableRow {
    /// Cells in this row. The first 3 cells are guaranteed to be shown but
    /// others might be cut on certain surfaces. Please test with the simulator
    /// to see which cells will be shown for a given surface.
    #[prost(message, repeated, tag="1")]
    pub cells: ::prost::alloc::vec::Vec<TableCell>,
    /// Indicates whether there should be a divider after each row.
    #[prost(bool, tag="2")]
    pub divider: bool,
}
/// Content to be shown.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Content {
    /// Content.
    #[prost(oneof="content::Content", tags="1, 2, 3, 4, 5, 6, 7")]
    pub content: ::core::option::Option<content::Content>,
}
/// Nested message and enum types in `Content`.
pub mod content {
    /// Content.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Content {
        /// A basic card.
        #[prost(message, tag="1")]
        Card(super::Card),
        /// An image.
        #[prost(message, tag="2")]
        Image(super::Image),
        /// Table card.
        #[prost(message, tag="3")]
        Table(super::Table),
        /// Response indicating a set of media to be played.
        #[prost(message, tag="4")]
        Media(super::Media),
        /// A response to be used for interactive canvas experience.
        #[prost(message, tag="5")]
        Canvas(super::Canvas),
        /// A card presenting a collection of options to select from.
        #[prost(message, tag="6")]
        Collection(super::Collection),
        /// A card presenting a list of options to select from.
        #[prost(message, tag="7")]
        List(super::List),
    }
}
/// Represents a simple prompt to be send to a user.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Simple {
    /// Optional. Represents the speech to be spoken to the user. Can be SSML or
    /// text to speech.
    /// If the "override" field in the containing prompt is "true", the speech
    /// defined in this field replaces the previous Simple prompt's speech.
    #[prost(string, tag="1")]
    pub speech: ::prost::alloc::string::String,
    /// Optional text to display in the chat bubble. If not given, a display
    /// rendering of the speech field above will be used. Limited to 640
    /// chars.
    /// If the "override" field in the containing prompt is "true", the text
    /// defined in this field replaces to the previous Simple prompt's text.
    #[prost(string, tag="2")]
    pub text: ::prost::alloc::string::String,
}
/// Input suggestion to be presented to the user.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Suggestion {
    /// Required. The text shown in the suggestion chip. When tapped, this text will be
    /// posted back to the conversation verbatim as if the user had typed it.
    /// Each title must be unique among the set of suggestion chips.
    /// Max 25 chars
    #[prost(string, tag="1")]
    pub title: ::prost::alloc::string::String,
}
/// Represent a response to a user.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Prompt {
    /// Optional. Mode for how this messages should be merged with previously
    /// defined messages.
    /// "false" will clear all previously defined messages (first and last
    /// simple, content, suggestions link and canvas) and add messages defined in
    /// this prompt.
    /// "true" will add messages defined in this prompt to messages defined in
    /// previous responses. Setting this field to "true" will also enable appending
    /// to some fields inside Simple prompts, the Suggestion prompt and the Canvas
    /// prompt (part of the Content prompt). The Content and Link messages will
    /// always be overwritten if defined in the prompt.
    /// Default value is "false".
    #[deprecated]
    #[prost(bool, tag="1")]
    pub append: bool,
    /// Optional. Mode for how this messages should be merged with previously
    /// defined messages.
    /// "true" clears all previously defined messages (first and last
    /// simple, content, suggestions link and canvas) and adds messages defined in
    /// this prompt.
    /// "false" adds messages defined in this prompt to messages defined in
    /// previous responses. Leaving this field to "false" also enables
    /// appending to some fields inside Simple prompts, the Suggestions prompt,
    /// and the Canvas prompt (part of the Content prompt). The Content and Link
    /// messages are always overwritten if defined in the prompt. Default
    /// value is "false".
    #[prost(bool, tag="8")]
    pub r#override: bool,
    /// Optional. The first voice and text-only response.
    #[prost(message, optional, tag="2")]
    pub first_simple: ::core::option::Option<Simple>,
    /// Optional. A content like a card, list or media to display to the user.
    #[prost(message, optional, tag="3")]
    pub content: ::core::option::Option<Content>,
    /// Optional. The last voice and text-only response.
    #[prost(message, optional, tag="4")]
    pub last_simple: ::core::option::Option<Simple>,
    /// Optional. Suggestions to be displayed to the user which will always appear
    /// at the end of the response.
    /// If the "override" field in the containing prompt is "false", the titles
    /// defined in this field will be added to titles defined in any previously
    /// defined suggestions prompts and duplicate values will be removed.
    #[prost(message, repeated, tag="5")]
    pub suggestions: ::prost::alloc::vec::Vec<Suggestion>,
    /// Optional. An additional suggestion chip that can link out to the associated app
    /// or site.
    /// The chip will be rendered with the title "Open <name>". Max 20 chars.
    #[prost(message, optional, tag="6")]
    pub link: ::core::option::Option<Link>,
    /// Optional. Represents a Interactive Canvas response to be sent to the user.
    #[prost(message, optional, tag="9")]
    pub canvas: ::core::option::Option<Canvas>,
}
/// Represents a slot.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Slot {
    /// The mode of the slot (required or optional). Can be set by developer.
    #[prost(enumeration="slot::SlotMode", tag="1")]
    pub mode: i32,
    /// The status of the slot.
    #[prost(enumeration="slot::SlotStatus", tag="2")]
    pub status: i32,
    /// The value of the slot. Changing this value in the response, will
    /// modify the value in slot filling.
    #[prost(message, optional, tag="3")]
    pub value: ::core::option::Option<::prost_types::Value>,
    /// Indicates if the slot value was collected on the last turn.
    /// This field is read-only.
    #[prost(bool, tag="4")]
    pub updated: bool,
    /// Optional. This prompt is sent to the user when needed to fill a required
    /// slot. This prompt overrides the existing prompt defined in the console.
    /// This field is not included in the webhook request.
    #[prost(message, optional, tag="5")]
    pub prompt: ::core::option::Option<Prompt>,
}
/// Nested message and enum types in `Slot`.
pub mod slot {
    /// Represents the mode of a slot, that is, if it is required or not.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum SlotMode {
        /// Fallback value when the usage field is not populated.
        ModeUnspecified = 0,
        /// Indicates that the slot is not required to complete slot filling.
        Optional = 1,
        /// Indicates that the slot is required to complete slot filling.
        Required = 2,
    }
    /// Represents the status of a slot.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum SlotStatus {
        /// Fallback value when the usage field is not populated.
        SlotUnspecified = 0,
        /// Indicates that the slot does not have any values. This status cannot be
        /// modified through the response.
        Empty = 1,
        /// Indicates that the slot value is invalid. This status can be set
        /// through the response.
        Invalid = 2,
        /// Indicates that the slot has a value. This status cannot be modified
        /// through the response.
        Filled = 3,
    }
}
/// Represents the current status of slot filling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SlotFillingStatus {
    /// Fallback value when the usage field is not populated.
    Unspecified = 0,
    /// The slots have been initialized but slot filling has not started.
    Initialized = 1,
    /// The slot values are being collected.
    Collecting = 2,
    /// All slot values are final and cannot be changed.
    Final = 4,
}
