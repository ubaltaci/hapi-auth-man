## hapi-auth-man

Based on [**hapi-auth-cookie**](https://github.com/spumko/hapi-auth-cookie) added

* ACL support
* Inject credentials into view context



###ACL Support

###Inject credentials into view context

On hapi 's `onPreResponse` event, if response object contains successful authentication and response type is view,

``request.auth.credentials`` injecting into the view context as a `credentials`

You can use it in templates files like;

```javascript
// in EJS
<% if (locals.credentials) { %>
    <h2><%= credentials.id %></h2>
<% } %>
```



###Authentication

Check out [hapi-auth-cookie](https://github.com/spumko/hapi-auth-cookie)