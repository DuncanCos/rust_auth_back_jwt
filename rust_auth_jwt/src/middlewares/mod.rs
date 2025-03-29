use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;

use log;


pub async fn test_middleware( req: Request, next: Next) -> impl IntoResponse {
   
   let is_valid= true;
    //println!("middleware connected : {is_valid}");
    log::info!("middleware connected {}",is_valid);
    log::warn!("test warinig");
    log::error!("test error");
    log::debug!("test debug");
      

    if is_valid {
        (StatusCode::UNAUTHORIZED, format!("not connected middleware")).into_response()
    }else{
        next.run(req).await
    }
    
}