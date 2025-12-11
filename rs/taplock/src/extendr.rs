use crate::TapLockError;

use crate::OAuth2Response;
use extendr_api::prelude::*;

fn from_json_value_to_robj(value: &serde_json::Value) -> Robj {
    match value {
        serde_json::Value::Null => NULL.into_robj(),
        serde_json::Value::Object(inner) => {
            let iter = inner.into_iter();
            let mut names = Vec::with_capacity(iter.len());
            let mut values = Vec::with_capacity(iter.len());
            for (key, value) in iter {
                names.push(key);
                values.push(from_json_value_to_robj(value));
            }
            let mut res = List::from_values(values);
            res.as_robj_mut()
                .set_names(names)
                .unwrap()
                .as_list()
                .unwrap()
        }
        .into_robj(),
        serde_json::Value::Bool(b) => b.into_robj(),
        serde_json::Value::Array(a) => {
            List::from_values(a.iter().map(from_json_value_to_robj)).into_robj()
        }
        serde_json::Value::Number(n) => n.as_f64().into_robj(),
        serde_json::Value::String(s) => s.into_robj(),
    }
}

impl IntoRobj for &OAuth2Response {
    fn into_robj(self) -> Robj {
        let fields = from_json_value_to_robj(&self.fields);
        list!(
            access_token = self.access_token.clone(),
            refresh_token = self.refresh_token.clone(),
            fields = fields
        )
        .into()
    }
}

impl From<TapLockError> for extendr_api::Error {
    fn from(item: TapLockError) -> extendr_api::Error {
        extendr_api::Error::Other(item.to_string())
    }
}

impl IntoRobj for TapLockError {
    fn into_robj(self) -> extendr_api::Robj {
        extendr_api::Strings::from(self.to_string()).into_robj()
    }
}
