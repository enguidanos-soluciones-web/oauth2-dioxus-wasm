use derive_more::Display;

#[derive(Debug, Display)]
pub enum Params {
    #[display("client_id")]
    ClientId,
    #[display("code")]
    Code,
    #[display("grant_type")]
    GrantType,
    #[display("response_type")]
    ResponseType,
    #[display("redirect_uri")]
    RedirectUri,
    #[display("response_mode")]
    ResponseMode,
    #[display("scope")]
    Scope,
    #[display("state")]
    State,
    #[display("code_challenge")]
    CodeChallenge,
    #[display("code_challenge_method")]
    CodeChallengeMethod,
    #[display("code_verifier")]
    CodeVerifier,
    #[display("refresh_token")]
    RefreshToken,
    #[display("nonce")]
    Nonce,
}
