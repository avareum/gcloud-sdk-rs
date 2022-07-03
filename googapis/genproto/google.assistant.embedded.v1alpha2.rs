/// The top-level message sent by the client. Clients must send at least two, and
/// typically numerous `AssistRequest` messages. The first message must
/// contain a `config` message and must not contain `audio_in` data. All
/// subsequent messages must contain `audio_in` data and must not contain a
/// `config` message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AssistRequest {
    /// Exactly one of these fields must be specified in each `AssistRequest`.
    #[prost(oneof="assist_request::Type", tags="1, 2")]
    pub r#type: ::core::option::Option<assist_request::Type>,
}
/// Nested message and enum types in `AssistRequest`.
pub mod assist_request {
    /// Exactly one of these fields must be specified in each `AssistRequest`.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        /// The `config` message provides information to the recognizer that
        /// specifies how to process the request.
        /// The first `AssistRequest` message must contain a `config` message.
        #[prost(message, tag="1")]
        Config(super::AssistConfig),
        /// The audio data to be recognized. Sequential chunks of audio data are sent
        /// in sequential `AssistRequest` messages. The first `AssistRequest`
        /// message must not contain `audio_in` data and all subsequent
        /// `AssistRequest` messages must contain `audio_in` data. The audio bytes
        /// must be encoded as specified in `AudioInConfig`.
        /// Audio must be sent at approximately real-time (16000 samples per second).
        /// An error will be returned if audio is sent significantly faster or
        /// slower.
        #[prost(bytes, tag="2")]
        AudioIn(::prost::alloc::vec::Vec<u8>),
    }
}
/// The top-level message received by the client. A series of one or more
/// `AssistResponse` messages are streamed back to the client.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AssistResponse {
    /// *Output-only* Indicates the type of event.
    #[prost(enumeration="assist_response::EventType", tag="1")]
    pub event_type: i32,
    /// *Output-only* The audio containing the Assistant's response to the query.
    #[prost(message, optional, tag="3")]
    pub audio_out: ::core::option::Option<AudioOut>,
    /// *Output-only* Contains the Assistant's visual response to the query.
    #[prost(message, optional, tag="4")]
    pub screen_out: ::core::option::Option<ScreenOut>,
    /// *Output-only* Contains the action triggered by the query with the
    /// appropriate payloads and semantic parsing.
    #[prost(message, optional, tag="6")]
    pub device_action: ::core::option::Option<DeviceAction>,
    /// *Output-only* This repeated list contains zero or more speech recognition
    /// results that correspond to consecutive portions of the audio currently
    /// being processed, starting with the portion corresponding to the earliest
    /// audio (and most stable portion) to the portion corresponding to the most
    /// recent audio. The strings can be concatenated to view the full
    /// in-progress response. When the speech recognition completes, this list
    /// will contain one item with `stability` of `1.0`.
    #[prost(message, repeated, tag="2")]
    pub speech_results: ::prost::alloc::vec::Vec<SpeechRecognitionResult>,
    /// *Output-only* Contains output related to the user's query.
    #[prost(message, optional, tag="5")]
    pub dialog_state_out: ::core::option::Option<DialogStateOut>,
    /// *Output-only* Debugging info for developer. Only returned if request set
    /// `return_debug_info` to true.
    #[prost(message, optional, tag="8")]
    pub debug_info: ::core::option::Option<DebugInfo>,
}
/// Nested message and enum types in `AssistResponse`.
pub mod assist_response {
    /// Indicates the type of event.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum EventType {
        /// No event specified.
        Unspecified = 0,
        /// This event indicates that the server has detected the end of the user's
        /// speech utterance and expects no additional speech. Therefore, the server
        /// will not process additional audio (although it may subsequently return
        /// additional results). The client should stop sending additional audio
        /// data, half-close the gRPC connection, and wait for any additional results
        /// until the server closes the gRPC connection.
        EndOfUtterance = 1,
    }
}
/// Debug info for developer. Only returned if request set `return_debug_info`
/// to true.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DebugInfo {
    /// The original JSON response from an Action-on-Google agent to Google server.
    /// See
    /// <https://developers.google.com/actions/reference/rest/Shared.Types/AppResponse.>
    /// It will only be populated if the request maker owns the AoG project and the
    /// AoG project is in preview mode.
    #[prost(string, tag="1")]
    pub aog_agent_to_assistant_json: ::prost::alloc::string::String,
}
/// Specifies how to process the `AssistRequest` messages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AssistConfig {
    /// *Required* Specifies how to format the audio that will be returned.
    #[prost(message, optional, tag="2")]
    pub audio_out_config: ::core::option::Option<AudioOutConfig>,
    /// *Optional* Specifies the desired format to use when server returns a
    /// visual screen response.
    #[prost(message, optional, tag="8")]
    pub screen_out_config: ::core::option::Option<ScreenOutConfig>,
    /// *Required* Represents the current dialog state.
    #[prost(message, optional, tag="3")]
    pub dialog_state_in: ::core::option::Option<DialogStateIn>,
    /// Device configuration that uniquely identifies a specific device.
    #[prost(message, optional, tag="4")]
    pub device_config: ::core::option::Option<DeviceConfig>,
    /// *Optional* Debugging parameters for the whole `Assist` RPC.
    #[prost(message, optional, tag="5")]
    pub debug_config: ::core::option::Option<DebugConfig>,
    #[prost(oneof="assist_config::Type", tags="1, 6")]
    pub r#type: ::core::option::Option<assist_config::Type>,
}
/// Nested message and enum types in `AssistConfig`.
pub mod assist_config {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        /// Specifies how to process the subsequent incoming audio. Required if
        /// \[AssistRequest.audio_in][google.assistant.embedded.v1alpha2.AssistRequest.audio_in\]
        /// bytes will be provided in subsequent requests.
        #[prost(message, tag="1")]
        AudioInConfig(super::AudioInConfig),
        /// The text input to be sent to the Assistant. This can be populated from a
        /// text interface if audio input is not available.
        #[prost(string, tag="6")]
        TextQuery(::prost::alloc::string::String),
    }
}
/// Specifies how to process the `audio_in` data that will be provided in
/// subsequent requests. For recommended settings, see the Google Assistant SDK
/// [best
/// practices](<https://developers.google.com/assistant/sdk/guides/service/python/best-practices/audio>).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AudioInConfig {
    /// *Required* Encoding of audio data sent in all `audio_in` messages.
    #[prost(enumeration="audio_in_config::Encoding", tag="1")]
    pub encoding: i32,
    /// *Required* Sample rate (in Hertz) of the audio data sent in all `audio_in`
    /// messages. Valid values are from 16000-24000, but 16000 is optimal.
    /// For best results, set the sampling rate of the audio source to 16000 Hz.
    /// If that's not possible, use the native sample rate of the audio source
    /// (instead of re-sampling).
    #[prost(int32, tag="2")]
    pub sample_rate_hertz: i32,
}
/// Nested message and enum types in `AudioInConfig`.
pub mod audio_in_config {
    /// Audio encoding of the data sent in the audio message.
    /// Audio must be one-channel (mono).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Encoding {
        /// Not specified. Will return result \[google.rpc.Code.INVALID_ARGUMENT][\].
        Unspecified = 0,
        /// Uncompressed 16-bit signed little-endian samples (Linear PCM).
        /// This encoding includes no header, only the raw audio bytes.
        Linear16 = 1,
        /// \[`FLAC`\](<https://xiph.org/flac/documentation.html>) (Free Lossless Audio
        /// Codec) is the recommended encoding because it is
        /// lossless--therefore recognition is not compromised--and
        /// requires only about half the bandwidth of `LINEAR16`. This encoding
        /// includes the `FLAC` stream header followed by audio data. It supports
        /// 16-bit and 24-bit samples, however, not all fields in `STREAMINFO` are
        /// supported.
        Flac = 2,
    }
}
/// Specifies the desired format for the server to use when it returns
/// `audio_out` messages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AudioOutConfig {
    /// *Required* The encoding of audio data to be returned in all `audio_out`
    /// messages.
    #[prost(enumeration="audio_out_config::Encoding", tag="1")]
    pub encoding: i32,
    /// *Required* The sample rate in Hertz of the audio data returned in
    /// `audio_out` messages. Valid values are: 16000-24000.
    #[prost(int32, tag="2")]
    pub sample_rate_hertz: i32,
    /// *Required* Current volume setting of the device's audio output.
    /// Valid values are 1 to 100 (corresponding to 1% to 100%).
    #[prost(int32, tag="3")]
    pub volume_percentage: i32,
}
/// Nested message and enum types in `AudioOutConfig`.
pub mod audio_out_config {
    /// Audio encoding of the data returned in the audio message. All encodings are
    /// raw audio bytes with no header, except as indicated below.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Encoding {
        /// Not specified. Will return result \[google.rpc.Code.INVALID_ARGUMENT][\].
        Unspecified = 0,
        /// Uncompressed 16-bit signed little-endian samples (Linear PCM).
        Linear16 = 1,
        /// MP3 audio encoding. The sample rate is encoded in the payload.
        Mp3 = 2,
        /// Opus-encoded audio wrapped in an ogg container. The result will be a
        /// file which can be played natively on Android and in some browsers (such
        /// as Chrome). The quality of the encoding is considerably higher than MP3
        /// while using the same bitrate. The sample rate is encoded in the payload.
        OpusInOgg = 3,
    }
}
/// Specifies the desired format for the server to use when it returns
/// `screen_out` response.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScreenOutConfig {
    /// Current visual screen-mode for the device while issuing the query.
    #[prost(enumeration="screen_out_config::ScreenMode", tag="1")]
    pub screen_mode: i32,
}
/// Nested message and enum types in `ScreenOutConfig`.
pub mod screen_out_config {
    /// Possible modes for visual screen-output on the device.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ScreenMode {
        /// No video mode specified.
        /// The Assistant may respond as if in `OFF` mode.
        Unspecified = 0,
        /// Screen is off (or has brightness or other settings set so low it is
        /// not visible). The Assistant will typically not return a screen response
        /// in this mode.
        Off = 1,
        /// The Assistant will typically return a partial-screen response in this
        /// mode.
        Playing = 3,
    }
}
/// Provides information about the current dialog state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DialogStateIn {
    /// *Required* This field must always be set to the
    /// \[DialogStateOut.conversation_state][google.assistant.embedded.v1alpha2.DialogStateOut.conversation_state\]
    /// value that was returned in the prior `Assist` RPC. It should only be
    /// omitted (field not set) if there was no prior `Assist` RPC because this is
    /// the first `Assist` RPC made by this device after it was first setup and/or
    /// a factory-default reset.
    #[prost(bytes="vec", tag="1")]
    pub conversation_state: ::prost::alloc::vec::Vec<u8>,
    /// *Required* Language of the request in
    /// [IETF BCP 47 syntax](<https://tools.ietf.org/html/bcp47>) (for example,
    /// "en-US"). See [Language
    /// Support](<https://developers.google.com/assistant/sdk/reference/rpc/languages>)
    /// for more information. If you have selected a language for this `device_id`
    /// using the
    /// \[Settings\](<https://developers.google.com/assistant/sdk/reference/assistant-app/assistant-settings>)
    /// menu in your phone's Google Assistant app, that selection will override
    /// this value.
    #[prost(string, tag="2")]
    pub language_code: ::prost::alloc::string::String,
    /// *Optional* Location of the device where the query originated.
    #[prost(message, optional, tag="5")]
    pub device_location: ::core::option::Option<DeviceLocation>,
    /// *Optional* If true, the server will treat the request as a new conversation
    /// and not use state from the prior request. Set this field to true when the
    /// conversation should be restarted, such as after a device reboot, or after a
    /// significant lapse of time since the prior query.
    #[prost(bool, tag="7")]
    pub is_new_conversation: bool,
}
/// *Required* Fields that identify the device to the Assistant.
///
/// See also:
///
/// *   [Register a Device - REST
/// API](<https://developers.google.com/assistant/sdk/reference/device-registration/register-device-manual>)
/// *   [Device Model and Instance
/// Schemas](<https://developers.google.com/assistant/sdk/reference/device-registration/model-and-instance-schemas>)
/// *   [Device
/// Proto](<https://developers.google.com/assistant/sdk/reference/rpc/google.assistant.devices.v1alpha2#device>)
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceConfig {
    /// *Required* Unique identifier for the device. The id length must be 128
    /// characters or less. Example: DBCDW098234. This MUST match the device_id
    /// returned from device registration. This device_id is used to match against
    /// the user's registered devices to lookup the supported traits and
    /// capabilities of this device. This information should not change across
    /// device reboots. However, it should not be saved across
    /// factory-default resets.
    #[prost(string, tag="1")]
    pub device_id: ::prost::alloc::string::String,
    /// *Required* Unique identifier for the device model. The combination of
    /// device_model_id and device_id must have been previously associated through
    /// device registration.
    #[prost(string, tag="3")]
    pub device_model_id: ::prost::alloc::string::String,
}
/// The audio containing the Assistant's response to the query. Sequential chunks
/// of audio data are received in sequential `AssistResponse` messages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AudioOut {
    /// *Output-only* The audio data containing the Assistant's response to the
    /// query. Sequential chunks of audio data are received in sequential
    /// `AssistResponse` messages.
    #[prost(bytes="vec", tag="1")]
    pub audio_data: ::prost::alloc::vec::Vec<u8>,
}
/// The Assistant's visual output response to query. Enabled by
/// `screen_out_config`.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ScreenOut {
    /// *Output-only* The format of the provided screen data.
    #[prost(enumeration="screen_out::Format", tag="1")]
    pub format: i32,
    /// *Output-only* The raw screen data to be displayed as the result of the
    /// Assistant query.
    #[prost(bytes="vec", tag="2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
/// Nested message and enum types in `ScreenOut`.
pub mod screen_out {
    /// Possible formats of the screen data.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Format {
        /// No format specified.
        Unspecified = 0,
        /// Data will contain a fully-formed HTML5 layout encoded in UTF-8, e.g.
        /// `<html><body><div>...</div></body></html>`. It is intended to be rendered
        /// along with the audio response. Note that HTML5 doctype should be included
        /// in the actual HTML data.
        Html = 1,
    }
}
/// The response returned to the device if the user has triggered a Device
/// Action. For example, a device which supports the query *Turn on the light*
/// would receive a `DeviceAction` with a JSON payload containing the semantics
/// of the request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceAction {
    /// JSON containing the device command response generated from the triggered
    /// Device Action grammar. The format is given by the
    /// `action.devices.EXECUTE` intent for a given
    /// \[trait\](<https://developers.google.com/assistant/sdk/reference/traits/>).
    #[prost(string, tag="1")]
    pub device_request_json: ::prost::alloc::string::String,
}
/// The estimated transcription of a phrase the user has spoken. This could be
/// a single segment or the full guess of the user's spoken query.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SpeechRecognitionResult {
    /// *Output-only* Transcript text representing the words that the user spoke.
    #[prost(string, tag="1")]
    pub transcript: ::prost::alloc::string::String,
    /// *Output-only* An estimate of the likelihood that the Assistant will not
    /// change its guess about this result. Values range from 0.0 (completely
    /// unstable) to 1.0 (completely stable and final). The default of 0.0 is a
    /// sentinel value indicating `stability` was not set.
    #[prost(float, tag="2")]
    pub stability: f32,
}
/// The dialog state resulting from the user's query. Multiple of these messages
/// may be received.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DialogStateOut {
    /// *Output-only* Supplemental display text from the Assistant. This could be
    /// the same as the speech spoken in `AssistResponse.audio_out` or it could
    /// be some additional information which aids the user's understanding.
    #[prost(string, tag="1")]
    pub supplemental_display_text: ::prost::alloc::string::String,
    /// *Output-only* State information for the subsequent `Assist` RPC. This
    /// value should be saved in the client and returned in the
    /// \[`DialogStateIn.conversation_state`\](#dialogstatein) field with the next
    /// `Assist` RPC. (The client does not need to interpret or otherwise use this
    /// value.) This information should be saved across device reboots. However,
    /// this value should be cleared (not saved in the client) during a
    /// factory-default reset.
    #[prost(bytes="vec", tag="2")]
    pub conversation_state: ::prost::alloc::vec::Vec<u8>,
    /// *Output-only* Specifies the mode of the microphone after this `Assist`
    /// RPC is processed.
    #[prost(enumeration="dialog_state_out::MicrophoneMode", tag="3")]
    pub microphone_mode: i32,
    /// *Output-only* Updated volume level. The value will be 0 or omitted
    /// (indicating no change) unless a voice command such as *Increase the volume*
    /// or *Set volume level 4* was recognized, in which case the value will be
    /// between 1 and 100 (corresponding to the new volume level of 1% to 100%).
    /// Typically, a client should use this volume level when playing the
    /// `audio_out` data, and retain this value as the current volume level and
    /// supply it in the `AudioOutConfig` of the next `AssistRequest`. (Some
    /// clients may also implement other ways to allow the current volume level to
    /// be changed, for example, by providing a knob that the user can turn.)
    #[prost(int32, tag="4")]
    pub volume_percentage: i32,
}
/// Nested message and enum types in `DialogStateOut`.
pub mod dialog_state_out {
    /// Possible states of the microphone after a `Assist` RPC completes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum MicrophoneMode {
        /// No mode specified.
        Unspecified = 0,
        /// The service is not expecting a follow-on question from the user.
        /// The microphone should remain off until the user re-activates it.
        CloseMicrophone = 1,
        /// The service is expecting a follow-on question from the user. The
        /// microphone should be re-opened when the `AudioOut` playback completes
        /// (by starting a new `Assist` RPC call to send the new audio).
        DialogFollowOn = 2,
    }
}
/// Debugging parameters for the current request.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DebugConfig {
    /// When this field is set to true, the `debug_info` field in `AssistResponse`
    /// may be populated. However it will significantly increase latency of
    /// responses. Do not set this field true in production code.
    #[prost(bool, tag="6")]
    pub return_debug_info: bool,
}
/// There are three sources of locations. They are used with this precedence:
///
/// 1. This `DeviceLocation`, which is primarily used for mobile devices with
///    GPS .
/// 2. Location specified by the user during device setup; this is per-user, per
///    device. This location is used if `DeviceLocation` is not specified.
/// 3. Inferred location based on IP address. This is used only if neither of the
///    above are specified.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeviceLocation {
    #[prost(oneof="device_location::Type", tags="1")]
    pub r#type: ::core::option::Option<device_location::Type>,
}
/// Nested message and enum types in `DeviceLocation`.
pub mod device_location {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        /// Latitude and longitude of device.
        #[prost(message, tag="1")]
        Coordinates(super::super::super::super::r#type::LatLng),
    }
}
/// Generated client implementations.
pub mod embedded_assistant_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service that implements the Google Assistant API.
    #[derive(Debug, Clone)]
    pub struct EmbeddedAssistantClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl EmbeddedAssistantClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> EmbeddedAssistantClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> EmbeddedAssistantClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
            >>::Error: Into<StdError> + Send + Sync,
        {
            EmbeddedAssistantClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        #[must_use]
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        #[must_use]
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        /// Initiates or continues a conversation with the embedded Assistant Service.
        /// Each call performs one round-trip, sending an audio request to the service
        /// and receiving the audio response. Uses bidirectional streaming to receive
        /// results, such as the `END_OF_UTTERANCE` event, while sending audio.
        ///
        /// A conversation is one or more gRPC connections, each consisting of several
        /// streamed requests and responses.
        /// For example, the user says *Add to my shopping list* and the Assistant
        /// responds *What do you want to add?*. The sequence of streamed requests and
        /// responses in the first gRPC message could be:
        ///
        /// *   AssistRequest.config
        /// *   AssistRequest.audio_in
        /// *   AssistRequest.audio_in
        /// *   AssistRequest.audio_in
        /// *   AssistRequest.audio_in
        /// *   AssistResponse.event_type.END_OF_UTTERANCE
        /// *   AssistResponse.speech_results.transcript "add to my shopping list"
        /// *   AssistResponse.dialog_state_out.microphone_mode.DIALOG_FOLLOW_ON
        /// *   AssistResponse.audio_out
        /// *   AssistResponse.audio_out
        /// *   AssistResponse.audio_out
        ///
        ///
        /// The user then says *bagels* and the Assistant responds
        /// *OK, I've added bagels to your shopping list*. This is sent as another gRPC
        /// connection call to the `Assist` method, again with streamed requests and
        /// responses, such as:
        ///
        /// *   AssistRequest.config
        /// *   AssistRequest.audio_in
        /// *   AssistRequest.audio_in
        /// *   AssistRequest.audio_in
        /// *   AssistResponse.event_type.END_OF_UTTERANCE
        /// *   AssistResponse.dialog_state_out.microphone_mode.CLOSE_MICROPHONE
        /// *   AssistResponse.audio_out
        /// *   AssistResponse.audio_out
        /// *   AssistResponse.audio_out
        /// *   AssistResponse.audio_out
        ///
        /// Although the precise order of responses is not guaranteed, sequential
        /// `AssistResponse.audio_out` messages will always contain sequential portions
        /// of audio.
        pub async fn assist(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::AssistRequest>,
        ) -> Result<
            tonic::Response<tonic::codec::Streaming<super::AssistResponse>>,
            tonic::Status,
        > {
            self.inner
                .ready()
                .await
                .map_err(|e| {
                    tonic::Status::new(
                        tonic::Code::Unknown,
                        format!("Service was not ready: {}", e.into()),
                    )
                })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.assistant.embedded.v1alpha2.EmbeddedAssistant/Assist",
            );
            self.inner.streaming(request.into_streaming_request(), path, codec).await
        }
    }
}
