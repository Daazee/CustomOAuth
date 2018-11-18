using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using CustomOAuth.Api.Models;
using CustomOAuth.Api.DAL;

namespace CustomOAuth.Api.Providers
{
    public class ApplicationOAuthProvider : OAuthAuthorizationServerProvider
    {
        private readonly string _publicClientId;
        CustomUserManager customUserManager;

        public ApplicationOAuthProvider(string publicClientId)
        {
            if (publicClientId == null)
            {
                throw new ArgumentNullException("publicClientId");
            }

            _publicClientId = publicClientId;
            customUserManager = new CustomUserManager();
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            //ApplicationUser user = await userManager.FindAsync(context.UserName, context.Password);
            //Custom Login 
          Tuple<bool,User> LoginResult = customUserManager.Login(context.UserName, context.Password);


            if (!LoginResult.Item1)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect.");
                return;
            }
            User user = LoginResult.Item2;
            /*ClaimsIdentity oAuthIdentity = await user.GenerateUserIdentityAsync(userManager,
               OAuthDefaults.AuthenticationType);
            ClaimsIdentity cookiesIdentity = await user.GenerateUserIdentityAsync(userManager,
                CookieAuthenticationDefaults.AuthenticationType);

            AuthenticationProperties properties = CreateProperties(user.UserName);
            AuthenticationTicket ticket = new AuthenticationTicket(oAuthIdentity, properties);
            context.Validated(ticket);
            context.Request.Context.Authentication.SignIn(cookiesIdentity);*/

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Email, context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

            foreach (var role in user.Roles)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
            }


            context.Validated(new AuthenticationTicket(identity, new AuthenticationProperties
            {
                Dictionary = {
                        { "roles", user.Roles.Count <= 1 ? user.Roles.FirstOrDefault() : user.Roles.Aggregate((previous, next) => $"{previous.ToString()},{next}") },
                        { "organisationname", user.Id.ToString() },
                        { "organisationid", user.Id.ToString() },
                        { "user_id", user.Id.ToString() },
                        { "username", context.UserName },
                        { "firstname", user.Username },
                        { "lastname", user.Username }


                    }
            }));




        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            // Resource owner password credentials does not provide a client ID.
            if (context.ClientId == null)
            {
                context.Validated();
            }

            return Task.FromResult<object>(null);
        }

        public override Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == _publicClientId)
            {
                Uri expectedRootUri = new Uri(context.Request.Uri, "/");

                if (expectedRootUri.AbsoluteUri == context.RedirectUri)
                {
                    context.Validated();
                }
            }

            return Task.FromResult<object>(null);
        }

        public static AuthenticationProperties CreateProperties(string userName)
        {
            IDictionary<string, string> data = new Dictionary<string, string>
            {
                { "userName", userName }
            };
            return new AuthenticationProperties(data);
        }
    }
}