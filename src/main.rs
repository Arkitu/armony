use std::error::Error;

type GenericError = Box<dyn Error + Send + Sync>;
type GenericResult = Result<(), GenericError>;

mod server {
    use std::{net::SocketAddr, sync::Arc};
    use crate::GenericError;

    use super::GenericResult;
    use tokio_native_tls::{TlsAcceptor, native_tls::{Identity, TlsAcceptor as BasicTlsAcceptor}};
    use tokio::{net::TcpListener, io::{AsyncRead, AsyncWrite, AsyncReadExt}, fs::File};
    use tokio_tungstenite::accept_async;

    async fn get_tls_acceptor(pfx_path:Option<String>) -> Result<TlsAcceptor, GenericError> {
        let mut file = File::open(pfx_path.unwrap_or("tls_keys/certificate.pfx".to_string())).await.unwrap();
        let mut certificate = vec![];
        file.read_to_end(&mut certificate).await.unwrap();
        let identity = Identity::from_pkcs12(&certificate, "fH\"Ux]XHgo&*&(g/S0$F").unwrap();
        Ok(tokio_native_tls::TlsAcceptor::from(BasicTlsAcceptor::builder(identity).build()?))
    }

    async fn handle_tls_connection<T>(tls_acceptor:Arc<TlsAcceptor>, raw_stream:T, addr:SocketAddr) -> GenericResult
    where
        T: AsyncRead + AsyncWrite + Unpin
    {
        let stream = tls_acceptor.accept(raw_stream).await?;
        handle_tcp_connection(stream, addr).await
    }

    async fn handle_tcp_connection<T>(raw_stream:T, addr:SocketAddr) -> GenericResult
    where
        T: AsyncRead + AsyncWrite + Unpin
    {
        println!("Incoming TCP connection from: {}", addr);

        let ws_stream = accept_async(raw_stream)
            .await
            .expect("Error during the websocket handshake occurred");
        println!("WebSocket connection established: {}", addr);

        Ok(())
    }

    async fn handle_connections(listener:TcpListener, tls_acceptor:Arc<TlsAcceptor>) {
        // Let's spawn the handling of each connection in a separate task.
        while let Ok((stream, addr)) = listener.accept().await {
            println!("New connection");
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                let connection = handle_tls_connection(tls_acceptor, stream, addr).await;
                if let Err(e) = connection {
                    eprintln!("Error during connection : {:?}", e)
                }
            });
        }
    }

    pub async fn run_server(addr:Option<SocketAddr>) -> GenericResult {
        let addr = addr.unwrap_or("127.0.0.1:8080".parse().unwrap());

        // Create the event loop and TCP listener we'll accept connections on.
        let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
        let tls_acceptor = Arc::new(get_tls_acceptor(Some("tls_keys/dev.pfx".to_string())).await?);

        tokio::spawn(handle_connections(listener, tls_acceptor));
        println!("Listening on: {}", addr);

        Ok(())
    }
}

mod client {
    use super::GenericError;
    use std::net::SocketAddr;
    use super::GenericResult;
    use tokio::{net::TcpStream, fs::File, io::AsyncReadExt};
    use tokio_native_tls::{native_tls::{TlsConnector as SyncTlsConnector, Certificate}, TlsConnector};

    async fn get_certificate(pem_path:Option<String>) -> Result<Certificate, GenericError> {
        let mut file = File::open(pem_path.unwrap_or("tls_keys/certificate.crt".to_string())).await.unwrap();
        let mut certificate = vec![];
        file.read_to_end(&mut certificate).await?;
        Ok(Certificate::from_pem(&certificate)?)
    }

    pub async fn run_client(addr:Option<SocketAddr>) -> GenericResult {
        let addr = addr.unwrap_or("127.0.0.1:8080".parse().unwrap());

        let tcp_stream = TcpStream::connect(&addr).await?;

        let certificate = get_certificate(Some("tls_keys/dev.crt".to_string())).await?;
        println!("certificate : {:?}", certificate.to_der());
        let tls_connector = SyncTlsConnector::builder().add_root_certificate(certificate).build()?;
        let tls_connector = TlsConnector::from(tls_connector);
    
        let mut tcp_stream = tls_connector.connect("127.0.0.1:8080", tcp_stream).await?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> GenericResult {
    server::run_server(None).await?;
    client::run_client(None).await?;
    Ok(())
}
