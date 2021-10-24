use crate::{
    database::{DatabaseError, Get, Insert},
    server::Server,
    Application, Error, Result,
};
use async_trait::async_trait;
use futures::{Stream, TryStreamExt};

#[async_trait]
impl Insert for Server {
    type Parent = Application;
    async fn insert(&self, app: &Self::Parent) -> Result<()> {
        let endpoint = self.api_endpoint.as_str();
        sqlx::query!(
            r#"
            INSERT INTO servers(api_endpoint, nickname)
            VALUES ($1, $2)
            "#,
            endpoint,
            self.nickname,
        )
        .execute(app.pool())
        .await
        // TODO: map to correct error
        .map_err(|_| Error::DatabaseError(DatabaseError::Other))?;
        Ok(())
    }
}

#[async_trait]
impl Get for Server {
    type Identifier = url::Url;
    type Parent = Application;
    type Stream<'a> = impl Stream<Item = Result<Server>> + 'a;

    fn get_all(app: &Self::Parent) -> Self::Stream<'_> {
        sqlx::query!(
            r#"
        SELECT api_endpoint AS endpoint, nickname FROM servers
        "#
        )
        .fetch(app.pool())
        .map_ok(move |record| {
            Server::from_values(record.endpoint, record.nickname, None)
                .expect("invalid server in database")
        })
        // TODO: map to correct error
        .map_err(|_| Error::DatabaseError(DatabaseError::Other))
    }

    async fn get(identifier: &Self::Identifier, parent: &Self::Parent) -> Result<Option<Self>> {
        let endpoint = identifier.as_str();
        Ok(sqlx::query!(
            r#"
        SELECT api_endpoint AS endpoint, nickname FROM servers
        WHERE api_endpoint = $1
        "#,
            endpoint
        )
        .fetch_optional(parent.pool())
        .await
        // TODO: map to correct error
        .map_err(|_| Error::DatabaseError(DatabaseError::Other))?
        .map(|record| {
            Self::from_values(record.endpoint, record.nickname, None)
                .expect("invalid server in database")
        }))
    }
}
