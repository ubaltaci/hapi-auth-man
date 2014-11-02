/**
 *
 * Created by uur on 14/07/14.
 */

// Load modules
var Async = require("async");
var Boom = require("boom");
var Hoek = require("hoek");
var _ = require("lodash");

var internals = {};
var policy;

exports.register = function (plugin, options, next) {

    policy = options.policy || {};

    // Inserting authenticated user into view context.
    plugin.ext("onPreResponse", function (request, next) {
        var response = request.response;
        // if response type view!
        if (request.auth && request.auth.isAuthenticated && response.variety && response.variety === "view") {
            response.source.context = response.source.context || {};
            response.source.context.credentials = request.auth.credentials;
        }
        return next();
    });

    plugin.expose("policy", function(newPolicy) {
        if(Object.keys(policy).length > 0) {
            _.extend(policy, newPolicy);
        }
        else {
            policy = newPolicy;
        }
    });

    // ACL part
    plugin.ext("onPostAuth", function (request, next) {


        // Get role & policies
        var roles = request.route.plugins["hapi-auth-man"] && request.route.plugins["hapi-auth-man"].roles;

        // Policy and role should exist to check authentication
        if (!policy || !roles || roles.length == 0) {
            return next();
        }

        roles.forEach(function (role) {
            if (!policy[role]) {
                return next(Boom.badImplementation(role + " not found in policies."));
            }
        });

        // Both exists, but is it authenticated ?
        if (!request.auth || !request.auth.isAuthenticated) {
            return next(Boom.unauthorized("You must be authenticated to do this."));
        }

        Async.eachSeries(roles, function (role, callback) {
            policy[role](request, callback);
        }, function(err) {
            if(err) {
                return next(Boom.forbidden(err));
            }
            return next();
        });
    });

    plugin.auth.scheme("cookie", internals.implementation);
    next();
};

internals.implementation = function (server, options) {

    Hoek.assert(options, "Missing cookie auth strategy options");
    Hoek.assert(!options.validateFunc || typeof options.validateFunc === "function", "Invalid validateFunc method in configuration");
    Hoek.assert(options.password, "Missing required password in configuration");

    var settings = Hoek.clone(options);                        // Options can be reused
    settings.cookie = settings.cookie || "sid";

    var cookieOptions = {
        encoding: "iron",
        password: settings.password,
        isSecure: settings.isSecure !== false,                  // Defaults to true
        path: "/",
        isHttpOnly: settings.isHttpOnly !== false               // Defaults to true
    };

    if (settings.ttl) {
        cookieOptions.ttl = settings.ttl;
    }

    if (settings.domain) {
        cookieOptions.domain = settings.domain;
    }

    if (typeof settings.appendNext === "boolean") {
        settings.appendNext = (settings.appendNext ? "next" : "");
    }

    server.state(settings.cookie, cookieOptions);

    server.ext("onPreAuth", function (request, reply) {

        request.auth.session = {
            set: function (session, ttl) {
                Hoek.assert(session && typeof session === "object", "Invalid session");

                if (ttl) {
                    reply.state(settings.cookie, session, {ttl: ttl});
                }
                else {
                    reply.state(settings.cookie, session);
                }
            },
            clear: function () {
                reply.unstate(settings.cookie);
            }
        };

        reply();
    });

    var scheme = {
        authenticate: function (request, reply) {

            var validate = function () {

                // Check cookie

                var session = request.state[settings.cookie];
                if (!session) {
                    return unauthenticated(Boom.unauthorized());
                }

                if (!settings.validateFunc) {
                    return reply(null, {credentials: session});
                }

                settings.validateFunc(session, function (err, isValid, credentials) {

                    if (err || !isValid) {

                        if (settings.clearInvalid) {
                            reply.unstate(settings.cookie);
                        }

                        return unauthenticated(Boom.unauthorized("Invalid cookie"), {
                            credentials: credentials,
                            log: (err ? {data: err} : "Failed validation")
                        });
                    }

                    return reply(null, {credentials: credentials || session});
                });
            };

            var unauthenticated = function (err, result) {

                if (settings.redirectOnTry === false &&             // Defaults to true
                    request.auth.mode === "try") {
                    return reply(err, result);
                }

                var redirectTo = settings.redirectTo;
                if (request.route.plugins["hapi-auth-man"] &&
                    request.route.plugins["hapi-auth-man"].redirectTo !== undefined) {
                    redirectTo = request.route.plugins["hapi-auth-man"].redirectTo;
                }

                if (!redirectTo) {
                    return reply(err, result);
                }

                var uri = redirectTo;
                if (settings.appendNext) {
                    if (uri.indexOf("?") !== -1) {
                        uri += "&";
                    }
                    else {
                        uri += "?";
                    }

                    uri += settings.appendNext + "=" + encodeURIComponent(request.url.path);
                }

                return reply("You are being redirected...", result).redirect(uri);
            };

            validate();
        }
    };

    return scheme;
};

exports.register.attributes = {
    pkg: require("../package.json")
};