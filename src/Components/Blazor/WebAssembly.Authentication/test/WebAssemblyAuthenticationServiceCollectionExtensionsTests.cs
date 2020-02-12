using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Blazor.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    public class WebAssemblyAuthenticationServiceCollectionExtensionsTests
    {
        [Fact]
        public void CanResolve_AccessTokenProvider()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            host.Services.GetRequiredService<IAccessTokenProvider>();
        }

        [Fact]
        public void CanResolve_IRemoteAuthenticationService()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            host.Services.GetRequiredService<IRemoteAuthenticationService<RemoteAuthenticationState>>();
        }

        [Fact]
        public void ApiAuthorizationOptions_ConfigurationDefaultsGetApplied()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<ApiAuthorizationProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("authentication/login", paths.LoginPath);
            Assert.Equal("authentication/login-callback", paths.LoginCallbackPath);
            Assert.Equal("authentication/login-failed", paths.LoginFailedPath);
            Assert.Equal("authentication/register", paths.RegisterPath);
            Assert.Equal("authentication/profile", paths.ProfilePath);
            Assert.Equal("Identity/Account/Register", paths.RemoteRegisterPath);
            Assert.Equal("Identity/Account/Manage", paths.RemoteProfilePath);
            Assert.Equal("authentication/logout", paths.LogoutPath);
            Assert.Equal("authentication/logout-callback", paths.LogoutCallbackPath);
            Assert.Equal("authentication/logout-failed", paths.LogoutFailedPath);
            Assert.Equal("authentication/logged-out", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("Microsoft.AspNetCore.Components.WebAssembly.Authentication.Tests", user.AuthenticationType);
            Assert.Equal("scope", user.ScopeClaim);
            Assert.Equal("scope", user.RoleClaim);
            Assert.Equal("name", user.NameClaim);

            Assert.Equal(
                "_configuration/Microsoft.AspNetCore.Components.WebAssembly.Authentication.Tests",
                options.Value.ProviderOptions.ConfigurationEndpoint);
        }

        [Fact]
        public void ApiAuthorizationOptions_DefaultsCanBeOverriden()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization(options =>
            {
                options.AuthenticationPaths = new RemoteAuthenticationApplicationPathsOptions
                {
                    LoginPath = "a",
                    LoginCallbackPath = "b",
                    LoginFailedPath = "c",
                    RegisterPath = "d",
                    ProfilePath = "e",
                    RemoteRegisterPath = "f",
                    RemoteProfilePath = "g",
                    LogoutPath = "h",
                    LogoutCallbackPath = "i",
                    LogoutFailedPath = "j",
                    LogoutSucceededPath = "k",
                };
                options.UserOptions = new RemoteAuthenticationUserOptions
                {
                    AuthenticationType = "l",
                    ScopeClaim = "m",
                    RoleClaim = "n",
                    NameClaim = "o",
                };
                options.ProviderOptions = new ApiAuthorizationProviderOptions
                {
                    ConfigurationEndpoint = "p"
                };
            });

            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<ApiAuthorizationProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("a", paths.LoginPath);
            Assert.Equal("b", paths.LoginCallbackPath);
            Assert.Equal("c", paths.LoginFailedPath);
            Assert.Equal("d", paths.RegisterPath);
            Assert.Equal("e", paths.ProfilePath);
            Assert.Equal("f", paths.RemoteRegisterPath);
            Assert.Equal("g", paths.RemoteProfilePath);
            Assert.Equal("h", paths.LogoutPath);
            Assert.Equal("i", paths.LogoutCallbackPath);
            Assert.Equal("j", paths.LogoutFailedPath);
            Assert.Equal("k", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("l", user.AuthenticationType);
            Assert.Equal("m", user.ScopeClaim);
            Assert.Equal("n", user.RoleClaim);
            Assert.Equal("o", user.NameClaim);

            Assert.Equal("p", options.Value.ProviderOptions.ConfigurationEndpoint);
        }

        [Fact]
        public void OidcOptions_ConfigurationDefaultsGetApplied()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.Replace(ServiceDescriptor.Singleton<NavigationManager, TestNavigationManager>());
            builder.Services.AddOidcAuthentication(options => { });
            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<OidcProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("authentication/login", paths.LoginPath);
            Assert.Equal("authentication/login-callback", paths.LoginCallbackPath);
            Assert.Equal("authentication/login-failed", paths.LoginFailedPath);
            Assert.Equal("authentication/register", paths.RegisterPath);
            Assert.Equal("authentication/profile", paths.ProfilePath);
            Assert.Null(paths.RemoteRegisterPath);
            Assert.Null(paths.RemoteProfilePath);
            Assert.Equal("authentication/logout", paths.LogoutPath);
            Assert.Equal("authentication/logout-callback", paths.LogoutCallbackPath);
            Assert.Equal("authentication/logout-failed", paths.LogoutFailedPath);
            Assert.Equal("authentication/logged-out", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Null(user.AuthenticationType);
            Assert.Null(user.ScopeClaim);
            Assert.Null(user.RoleClaim);
            Assert.Equal("name", user.NameClaim);

            var provider = options.Value.ProviderOptions;
            Assert.Null(provider.Authority);
            Assert.Null(provider.ClientId);
            Assert.Equal(new[] { "openid", "profile" }, provider.DefaultScopes);
            Assert.Equal("https://www.example.com/base/authentication/login-callback", provider.RedirectUri);
            Assert.Equal("https://www.example.com/base/authentication/logout-callback", provider.PostLogoutRedirectUri);
        }

        [Fact]
        public void OidcOptions_DefaultsCanBeOverriden()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddOidcAuthentication(options =>
            {
                options.AuthenticationPaths = new RemoteAuthenticationApplicationPathsOptions
                {
                    LoginPath = "a",
                    LoginCallbackPath = "b",
                    LoginFailedPath = "c",
                    RegisterPath = "d",
                    ProfilePath = "e",
                    RemoteRegisterPath = "f",
                    RemoteProfilePath = "g",
                    LogoutPath = "h",
                    LogoutCallbackPath = "i",
                    LogoutFailedPath = "j",
                    LogoutSucceededPath = "k",
                };
                options.UserOptions = new RemoteAuthenticationUserOptions
                {
                    AuthenticationType = "l",
                    ScopeClaim = "m",
                    RoleClaim = "n",
                    NameClaim = "o",
                };
                options.ProviderOptions = new OidcProviderOptions
                {
                    Authority = "p",
                    ClientId = "q",
                    DefaultScopes = Array.Empty<string>(),
                    RedirectUri = "https://www.example.com/base/custom-login",
                    PostLogoutRedirectUri = "https://www.example.com/base/custom-logout",
                };
            });

            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<OidcProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("a", paths.LoginPath);
            Assert.Equal("b", paths.LoginCallbackPath);
            Assert.Equal("c", paths.LoginFailedPath);
            Assert.Equal("d", paths.RegisterPath);
            Assert.Equal("e", paths.ProfilePath);
            Assert.Equal("f", paths.RemoteRegisterPath);
            Assert.Equal("g", paths.RemoteProfilePath);
            Assert.Equal("h", paths.LogoutPath);
            Assert.Equal("i", paths.LogoutCallbackPath);
            Assert.Equal("j", paths.LogoutFailedPath);
            Assert.Equal("k", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("l", user.AuthenticationType);
            Assert.Equal("m", user.ScopeClaim);
            Assert.Equal("n", user.RoleClaim);
            Assert.Equal("o", user.NameClaim);

            var provider = options.Value.ProviderOptions;
            Assert.Equal("p", provider.Authority);
            Assert.Equal("q", provider.ClientId);
            Assert.Equal(Array.Empty<string>(), provider.DefaultScopes);
            Assert.Equal("https://www.example.com/base/custom-login", provider.RedirectUri);
            Assert.Equal("https://www.example.com/base/custom-logout", provider.PostLogoutRedirectUri);
        }

        private class TestNavigationManager : NavigationManager
        {
            public TestNavigationManager()
            {
                Initialize("https://www.example.com/base/", "https://www.example.com/base/counter");
            }

            protected override void NavigateToCore(string uri, bool forceLoad) => throw new System.NotImplementedException();
        }
    }
}
