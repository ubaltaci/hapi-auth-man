## hapi-auth-man

Based on [**hapi-auth-cookie**](https://github.com/spumko/hapi-auth-cookie) added

* ACL support
* Inject credentials into view context



###ACL Support

After initializing this plugin, you can set roles like ``plugins.plugin["hapi-auth-man"].roles = roles``

``roles`` must be object which keys specifies roles, values are promise returned functions.



```javascript
roles = {
	"superadmin": function(request, database) {
		database.getUser(request.auth.credentials.id).then(function (user)) {
			if ( user.isSuperAdmin ) {
				return true;
			}
			return false;
		}.catch(function (e)) {
			return false;
		}			
	},
	"admin": function(request, database) {
		
 	}
	...
}
```



###Inject credentials into view context

On hapi 's `onPreResponse` event, if response object contains successful authentication and response type is view,

`request.auth.credentials` injecting into the view context as a `credentials`

You can use it in templates files like;

```
// in EJS
<% if (locals.credentials) { %>
    <h2><%= credentials.id %></h2>
<% } %>
```



###Authentication

Check out [hapi-auth-cookie](https://github.com/spumko/hapi-auth-cookie)