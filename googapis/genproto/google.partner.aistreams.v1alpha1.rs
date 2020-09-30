/// Cluster resource.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cluster {
    /// The name of the cluster. The format of cluster is:
    /// projects/<projectid>/locations/<locationid>/clusters/<clusterid>.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// Output only. The time at which this cluster was created.
    #[prost(message, optional, tag = "2")]
    pub create_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Output only. The time at which this cluster was updated.
    #[prost(message, optional, tag = "3")]
    pub update_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Labels with user-defined metadata.
    #[prost(map = "string, string", tag = "4")]
    pub labels: ::std::collections::HashMap<std::string::String, std::string::String>,
    /// Output only. The certificate for creating the secure connection between the client and
    /// the AI Streams data plane.
    #[prost(string, tag = "5")]
    pub certificate: std::string::String,
    /// Output only. The endpoint of the data plane cluster.
    #[prost(string, tag = "6")]
    pub service_endpoint: std::string::String,
}
/// Request message for 'ListClusters'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListClustersRequest {
    /// Required. The parent that owns the collection of Clusters.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Maximum number of Clusters to return.
    #[prost(int32, tag = "2")]
    pub page_size: i32,
    /// Page token received from a previous `ListClusters` call. Provide this to
    /// retrieve the subsequent page. When paginating, all other parameters
    /// provided to `ListClusters` must match the call that provided the page
    /// token.
    #[prost(string, tag = "3")]
    pub page_token: std::string::String,
    /// Filter request.
    #[prost(string, tag = "4")]
    pub filter: std::string::String,
    /// Order by fields for the result.
    #[prost(string, tag = "5")]
    pub order_by: std::string::String,
}
/// Response message from 'ListClusters'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListClustersResponse {
    /// List of clusters.
    #[prost(message, repeated, tag = "1")]
    pub clusters: ::std::vec::Vec<Cluster>,
    /// A token, which can be sent as `page_token` to retrieve the next page.
    /// If this field is omitted, there are no subsequent pages.
    #[prost(string, tag = "2")]
    pub next_page_token: std::string::String,
    /// Locations that could not be reached.
    #[prost(string, repeated, tag = "3")]
    pub unreachable: ::std::vec::Vec<std::string::String>,
}
/// Request message for 'GetCluster'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetClusterRequest {
    /// Required. The name of the Cluster resource to get.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
}
/// Request message for 'CreateCluster'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateClusterRequest {
    /// Required. The parent that owns the collection of Clusters.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Required. The cluster identifier.
    #[prost(string, tag = "2")]
    pub cluster_id: std::string::String,
    /// Required. The cluster resource to create.
    #[prost(message, optional, tag = "3")]
    pub cluster: ::std::option::Option<Cluster>,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes since the first request.
    ///
    /// For example, consider a situation where you make an initial request and the
    /// request times out. If you make the request again with the same request ID,
    /// the server can check if original operation with the same request ID was
    /// received, and if so, will ignore the second request. This prevents clients
    /// from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "4")]
    pub request_id: std::string::String,
}
/// Request message for 'UpdateCluster'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateClusterRequest {
    /// Required. Field mask is used to specify the fields to be overwritten in the
    /// Cluster resource by the update.
    /// The fields specified in the update_mask are relative to the resource, not
    /// the full request. A field will be overwritten if it is in the mask. If the
    /// user does not provide a mask then all fields will be overwritten.
    #[prost(message, optional, tag = "1")]
    pub update_mask: ::std::option::Option<::prost_types::FieldMask>,
    /// Required. The Cluster resource to update.
    #[prost(message, optional, tag = "2")]
    pub cluster: ::std::option::Option<Cluster>,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes since the first request.
    ///
    /// For example, consider a situation where you make an initial request and the
    /// request times out. If you make the request again with the same request ID,
    /// the server can check if original operation with the same request ID was
    /// received, and if so, will ignore the second request. This prevents clients
    /// from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "3")]
    pub request_id: std::string::String,
}
/// Request message for 'DeleteCluster'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteClusterRequest {
    /// Required. The name of cluster to delete.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes after the first request.
    ///
    /// For example, consider a situation where you make an initial request and the
    /// request times out. If you make the request again with the same request ID,
    /// the server can check if original operation with the same request ID was
    /// received, and if so, will ignore the second request. This prevents clients
    /// from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "2")]
    pub request_id: std::string::String,
}
/// Stream resource.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Stream {
    /// The name of the stream. The format for the full name is:
    /// projects/<projectid>/location/<locationid>/clusters/<clusterid>/streams/<streamid>.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// Output only. The time at which this Stream was created.
    #[prost(message, optional, tag = "2")]
    pub create_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Output only. The time at which this Stream was updated.
    #[prost(message, optional, tag = "3")]
    pub update_time: ::std::option::Option<::prost_types::Timestamp>,
    /// The labels of the stream.
    #[prost(map = "string, string", tag = "4")]
    pub labels: ::std::collections::HashMap<std::string::String, std::string::String>,
}
/// Request message for 'ListStreams'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStreamsRequest {
    /// Required. The parent that owns the collection of the Streams.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Maximum number of Streams to return.
    #[prost(int32, tag = "2")]
    pub page_size: i32,
    /// Page token received from a previous `ListStreams` call. Provide this to
    /// retrieve the subsequent page. When paginating, all other parameters
    /// provided to `ListClusters` must match the call that provided the page
    /// token.
    #[prost(string, tag = "3")]
    pub page_token: std::string::String,
    /// Filter request.
    #[prost(string, tag = "4")]
    pub filter: std::string::String,
    /// Order by fields for the result.
    #[prost(string, tag = "5")]
    pub order_by: std::string::String,
}
/// Response message from 'ListStreams'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStreamsResponse {
    /// List of the streams.
    #[prost(message, repeated, tag = "1")]
    pub streams: ::std::vec::Vec<Stream>,
    /// A token, which can be sent as `page_token` to retrieve the next page.
    /// If this field is omitted, there are no subsequent pages.
    #[prost(string, tag = "2")]
    pub next_page_token: std::string::String,
    /// Locations that could not be reached.
    #[prost(string, repeated, tag = "3")]
    pub unreachable: ::std::vec::Vec<std::string::String>,
}
/// Request message for 'GetStream'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetStreamRequest {
    /// Required. The name of the stream.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
}
/// Request message for 'CreateStream'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateStreamRequest {
    /// Required. The parent that owns the collection of streams.
    #[prost(string, tag = "1")]
    pub parent: std::string::String,
    /// Required. The stream identifier.
    #[prost(string, tag = "2")]
    pub stream_id: std::string::String,
    /// Required. The stream to create.
    #[prost(message, optional, tag = "3")]
    pub stream: ::std::option::Option<Stream>,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes since the first request.
    ///
    /// For example, consider a situation where you make an initial request and t
    /// he request times out. If you make the request again with the same request
    /// ID, the server can check if original operation with the same request ID
    /// was received, and if so, will ignore the second request. This prevents
    /// clients from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "4")]
    pub request_id: std::string::String,
}
/// Request message for 'UpdateStream'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateStreamRequest {
    /// Required. Field mask is used to specify the fields to be overwritten in the
    /// Stream resource by the update.
    /// The fields specified in the update_mask are relative to the resource, not
    /// the full request. A field will be overwritten if it is in the mask. If the
    /// user does not provide a mask then all fields will be overwritten.
    #[prost(message, optional, tag = "1")]
    pub update_mask: ::std::option::Option<::prost_types::FieldMask>,
    /// Required. The stream resource to update.
    #[prost(message, optional, tag = "2")]
    pub stream: ::std::option::Option<Stream>,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes since the first request.
    ///
    /// For example, consider a situation where you make an initial request and t
    /// he request times out. If you make the request again with the same request
    /// ID, the server can check if original operation with the same request ID
    /// was received, and if so, will ignore the second request. This prevents
    /// clients from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "3")]
    pub request_id: std::string::String,
}
/// Request message for 'DeleteStream'.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteStreamRequest {
    /// Required. The name of the stream.
    #[prost(string, tag = "1")]
    pub name: std::string::String,
    /// Optional. An optional request ID to identify requests. Specify a unique request ID
    /// so that if you must retry your request, the server will know to ignore
    /// the request if it has already been completed. The server will guarantee
    /// that for at least 60 minutes after the first request.
    ///
    /// For example, consider a situation where you make an initial request and t
    /// he request times out. If you make the request again with the same request
    /// ID, the server can check if original operation with the same request ID
    /// was received, and if so, will ignore the second request. This prevents
    /// clients from accidentally creating duplicate commitments.
    ///
    /// The request ID must be a valid UUID with the exception that zero UUID is
    /// not supported (00000000-0000-0000-0000-000000000000).
    #[prost(string, tag = "2")]
    pub request_id: std::string::String,
}
/// Represents the metadata of the long-running operation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OperationMetadata {
    /// Output only. The time the operation was created.
    #[prost(message, optional, tag = "1")]
    pub create_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Output only. The time the operation finished running.
    #[prost(message, optional, tag = "2")]
    pub end_time: ::std::option::Option<::prost_types::Timestamp>,
    /// Output only. Server-defined resource path for the target of the operation.
    #[prost(string, tag = "3")]
    pub target: std::string::String,
    /// Output only. Name of the verb executed by the operation.
    #[prost(string, tag = "4")]
    pub verb: std::string::String,
    /// Output only. Human-readable status of the operation, if any.
    #[prost(string, tag = "5")]
    pub status_message: std::string::String,
    /// Output only. Identifies whether the user has requested cancellation
    /// of the operation. Operations that have successfully been cancelled
    /// have [Operation.error][] value with a [google.rpc.Status.code][google.rpc.Status.code] of 1,
    /// corresponding to `Code.CANCELLED`.
    #[prost(bool, tag = "6")]
    pub requested_cancellation: bool,
    /// Output only. API version used to start the operation.
    #[prost(string, tag = "7")]
    pub api_version: std::string::String,
}
#[doc = r" Generated client implementations."]
pub mod ai_streams_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    #[doc = " AIStreams service."]
    pub struct AiStreamsClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl<T> AiStreamsClient<T>
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
        #[doc = " Lists Clusters in a given project and location."]
        pub async fn list_clusters(
            &mut self,
            request: impl tonic::IntoRequest<super::ListClustersRequest>,
        ) -> Result<tonic::Response<super::ListClustersResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.partner.aistreams.v1alpha1.AIStreams/ListClusters",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Gets details of a single Cluster."]
        pub async fn get_cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::GetClusterRequest>,
        ) -> Result<tonic::Response<super::Cluster>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.partner.aistreams.v1alpha1.AIStreams/GetCluster",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Creates a new Cluster in a given project and location."]
        pub async fn create_cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateClusterRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/CreateCluster",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Updates the parameters of a single Cluster."]
        pub async fn update_cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdateClusterRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/UpdateCluster",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Deletes a single Cluster."]
        pub async fn delete_cluster(
            &mut self,
            request: impl tonic::IntoRequest<super::DeleteClusterRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/DeleteCluster",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Lists Streams in a given project, location and cluster."]
        pub async fn list_streams(
            &mut self,
            request: impl tonic::IntoRequest<super::ListStreamsRequest>,
        ) -> Result<tonic::Response<super::ListStreamsResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.partner.aistreams.v1alpha1.AIStreams/ListStreams",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Gets details of a single Stream."]
        pub async fn get_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::GetStreamRequest>,
        ) -> Result<tonic::Response<super::Stream>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/google.partner.aistreams.v1alpha1.AIStreams/GetStream",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Creates a new Stream in a given project and location."]
        pub async fn create_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateStreamRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/CreateStream",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Updates the parameters of a single Stream."]
        pub async fn update_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::UpdateStreamRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/UpdateStream",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Deletes a single Stream."]
        pub async fn delete_stream(
            &mut self,
            request: impl tonic::IntoRequest<super::DeleteStreamRequest>,
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
                "/google.partner.aistreams.v1alpha1.AIStreams/DeleteStream",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for AiStreamsClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for AiStreamsClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "AiStreamsClient {{ ... }}")
        }
    }
}
