// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    /// <summary>
    /// Represents the result of trying to provision an access token.
    /// </summary>
    public class AccessTokenResult
    {
        /// <summary>
        /// Gets or sets the status of the current operation. See <see cref="AccessTokenResultStatus"/> for a list of statuses.
        /// </summary>
        public string Status { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="AccessToken"/> if <see cref="Status"/> is <see cref="AccessTokenResultStatus.Success"/>.
        /// </summary>
        public AccessToken Token { get; set; }

        /// <summary>
        /// Gets or sets the URL to redirect to if <see cref="Status"/> is <see cref="AccessTokenResultStatus.RequiresRedirect"/>.
        /// </summary>
        public string RedirectUrl { get; set; }

        /// <summary>
        /// Determines whether the token request was successful and makes the <see cref="AccessToken"/> available for use when it is.
        /// </summary>
        /// <param name="accessToken">The <see cref="AccessToken"/> if the request was successful.</param>
        /// <returns><c>true</c> when the token request is successful; <c>false</c> otherwise.</returns>
        public bool TryGetAccessToken(out AccessToken accessToken)
        {
            if (string.Equals(Status, AccessTokenResultStatus.Success, StringComparison.OrdinalIgnoreCase))
            {
                accessToken = Token;
                return true;
            }
            else
            {
                accessToken = null;
                return false;
            }
        }
    }
}
