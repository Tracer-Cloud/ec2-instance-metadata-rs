use serde_json::Value;
extern crate ureq;

#[derive(Clone, Copy)]
enum MetadataUrls {
    InstanceId,
    AmiId,
    AccountId,
    AvailabilityZone,
    InstanceType,
    Hostname,
    LocalHostname,
    PublicHostname,
}

#[allow(clippy::from_over_into)]
impl Into<&'static str> for MetadataUrls {
    fn into(self) -> &'static str {
        match self {
            MetadataUrls::InstanceId => "http://169.254.169.254/latest/meta-data/instance-id",
            MetadataUrls::AmiId => "http://169.254.169.254/latest/meta-data/ami-id",
            MetadataUrls::AccountId => {
                "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info"
            }
            MetadataUrls::AvailabilityZone => {
                "http://169.254.169.254/latest/meta-data/placement/availability-zone"
            }
            MetadataUrls::InstanceType => "http://169.254.169.254/latest/meta-data/instance-type",
            MetadataUrls::Hostname => "http://169.254.169.254/latest/meta-data/hostname",
            MetadataUrls::LocalHostname => "http://169.254.169.254/latest/meta-data/local-hostname",
            MetadataUrls::PublicHostname => {
                "http://169.254.169.254/latest/meta-data/public-hostname"
            }
        }
    }
}

fn identity_credentials_to_account_id(ident_creds: &str) -> Result<String> {
    let parsed: Value =
        serde_json::from_str(ident_creds).map_err(|e| Error::JsonError(format!("{:?}", e)))?;

    parsed["AccountId"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::JsonError("Missing AccountId field".into()))
}

fn availability_zone_to_region(availability_zone: &str) -> Result<&'static str> {
    const REGIONS: &[&str] = &[
        "ap-south-1",
        "eu-west-3",
        "eu-north-1",
        "eu-west-2",
        "eu-west-1",
        "ap-northeast-3",
        "ap-northeast-2",
        "ap-northeast-1",
        "sa-east-1",
        "ca-central-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "eu-central-1",
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "cn-north-1",
        "cn-northwest-1",
    ];

    for region in REGIONS {
        if availability_zone.starts_with(region) {
            return Ok(region);
        }
    }

    Err(Error::UnknownAvailabilityZone(
        availability_zone.to_string(),
    ))
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum Error {
    HttpRequest(String),
    IoError(String),
    UnknownAvailabilityZone(String),
    JsonError(String),
    NotFound(&'static str), // Reported for static URIs we fetch.
}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Error {
        Error::HttpRequest(format!("{:?}", error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(format!("{:?}", error))
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Error {
        Error::JsonError(format!("{:?}", error))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::HttpRequest(s) => write!(f, "Http Request Error: {}", s),
            Error::IoError(s) => write!(f, "IO Error: {}", s),
            Error::UnknownAvailabilityZone(s) => write!(f, "Unknown AvailabilityZone: {}", s),
            Error::JsonError(s) => write!(f, "JSON parsing error: {}", s),
            Error::NotFound(s) => write!(f, "Not found: {}", s),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

const REQUEST_TIMEOUT_MS: u64 = 2000; // 2 seconds

/// `InstanceMetadataClient` provides an API for fetching common fields
/// from the EC2 Instance Metadata API: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
///
/// # Examples:
/// ```
/// use ec2_instance_metadata::InstanceMetadataClient;
/// let client = ec2_instance_metadata::InstanceMetadataClient::new();
/// let instance_metadata = client.get().expect("Couldn't get the instance metadata.");
/// ````

#[derive(Debug)]
pub struct InstanceMetadataClient {
    agent: ureq::Agent,
}
impl InstanceMetadataClient {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_connect(Some(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS)))
            .timeout_global(Some(std::time::Duration::from_millis(REQUEST_TIMEOUT_MS)))
            .build()
            .new_agent();

        Self { agent }
    }

    fn get_token(&self) -> Result<String> {
        const TOKEN_API_URL: &str = "http://169.254.169.254/latest/api/token";

        let mut resp = self
            .agent
            .put(TOKEN_API_URL)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .send_empty()?;

        let token = resp.body_mut().read_to_string()?;
        Ok(token)
    }

    /// Get the instance metadata for the machine.
    pub fn get(&self) -> Result<InstanceMetadata> {
        let token = self.get_token()?;
        let instance_id = match self
            .agent
            .get::<&'static str>(MetadataUrls::InstanceId.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut instance_id_resp) => instance_id_resp.body_mut().read_to_string()?,
            Err(_) => return Err(Error::NotFound(MetadataUrls::InstanceId.into())),
        };

        let account_id = match self
            .agent
            .get::<&'static str>(MetadataUrls::AccountId.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut ident_creds_resp) => {
                let ident_creds = ident_creds_resp.body_mut().read_to_string()?;
                identity_credentials_to_account_id(&ident_creds)?
            }
            Err(_) => return Err(Error::NotFound(MetadataUrls::AccountId.into())),
        };

        let ami_id = match self
            .agent
            .get::<&'static str>(MetadataUrls::AmiId.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut ami_id_resp) => ami_id_resp.body_mut().read_to_string()?,
            Err(_) => return Err(Error::NotFound(MetadataUrls::AmiId.into())),
        };

        let (availability_zone, region) = match self
            .agent
            .get::<&'static str>(MetadataUrls::AvailabilityZone.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut availability_zone_resp) => {
                let zone = availability_zone_resp.body_mut().read_to_string()?;
                let region = availability_zone_to_region(&zone)?;
                (zone, region)
            }
            Err(_) => return Err(Error::NotFound(MetadataUrls::AvailabilityZone.into())),
        };

        let instance_type = match self
            .agent
            .get::<&'static str>(MetadataUrls::InstanceType.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut instance_type_resp) => instance_type_resp.body_mut().read_to_string()?,
            Err(_) => return Err(Error::NotFound(MetadataUrls::InstanceType.into())),
        };

        let hostname = match self
            .agent
            .get::<&'static str>(MetadataUrls::Hostname.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut hostname_resp) => hostname_resp.body_mut().read_to_string()?,
            Err(_) => return Err(Error::NotFound(MetadataUrls::Hostname.into())),
        };

        let local_hostname = match self
            .agent
            .get::<&'static str>(MetadataUrls::LocalHostname.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut local_hostname_resp) => local_hostname_resp.body_mut().read_to_string()?,
            Err(_) => return Err(Error::NotFound(MetadataUrls::LocalHostname.into())),
        };

        // "public-hostname" isn't always available - the instance must be configured
        // to support having one assigned.
        let public_hostname = match self
            .agent
            .get::<&'static str>(MetadataUrls::PublicHostname.into())
            .header("X-aws-ec2-metadata-token", &token)
            .call()
        {
            Ok(mut public_hostname_resp) => Some(public_hostname_resp.body_mut().read_to_string()?),
            Err(_) => None,
        };

        let metadata = InstanceMetadata {
            region,
            availability_zone,
            instance_id,
            account_id,
            ami_id,
            instance_type,
            hostname,
            local_hostname,
            public_hostname,
        };

        Ok(metadata)
    }
}

/// `InstanceMetadata` holds the fetched instance metadata. Fields
/// on this struct may be incomplete if AWS has updated the fields
/// or if they haven't been explicitly provided.
#[derive(Debug, Clone)]
pub struct InstanceMetadata {
    /// AWS Region - always available
    pub region: &'static str,

    /// AWS Availability Zone - always available
    pub availability_zone: String,

    /// AWS Instance Id - always available
    pub instance_id: String,

    /// AWS Account Id - always available, marked as Internal Only per:
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
    pub account_id: String,

    /// AWS AMS Id - always available
    pub ami_id: String,

    /// AWS Instance Type - always available
    pub instance_type: String,

    /// AWS Instance Local Hostname - always available
    pub local_hostname: String,

    /// AWS Instance Hostname - always available
    pub hostname: String,

    /// AWS Instance Public Hostname - optionally available
    pub public_hostname: Option<String>,
}

impl std::fmt::Display for InstanceMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for InstanceMetadataClient {
    fn default() -> Self {
        Self::new()
    }
}
