import { signalStore, withComputed, withHooks, withMethods, withState, patchState } from '@ngrx/signals'
import { AuthState, initialAuthState, User } from './auth.model';
import { effect, inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { environment } from '../environment';
// IMPORTANT: For production, use a more robust PKCE library or Web Cryptography API
// This is a simplified PKCE implementation for demonstration.
// For example, see: [https://github.com/auth0/auth0-spa-js/blob/master/src/utils.ts](https://github.com/auth0/auth0-spa-js/blob/master/src/utils.ts)
// Or use 'pkce-challenge' npm package for Node.js if generating on backend.
// For browser, use window.crypto.subtle
import * as sha256 from 'js-sha256'; // npm install js-sha256

const AUTH_KEY = "auth";
const ACCESS_TOKEN_KEY = 'accessToken';
const TOKEN_EXIPIRY_KEY = "expiresIn";

const GOOGLE_CLIENT_ID = environment.GOOGLE_CLIENT_ID;

export const AuthStore = signalStore(
    { providedIn: 'root' },
    withState<AuthState>(initialAuthState),
    withComputed((store) => ({})),
    withMethods((store) => {

        const platformId = inject(PLATFORM_ID);
        const isBrowser = isPlatformBrowser(platformId);

        // PKCE Helper (simplified for demonstration)
        async function generatePkcePair(): Promise<{ verifier: string; challenge: string }> {
            const generateRandomString = (length: number) => {
                let text = '';
                const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
                for (let i = 0; i < length; i++) {
                    text += possible.charAt(Math.floor(Math.random() * possible.length));
                }
                return text;
            };

            const verifier = generateRandomString(128); // Length between 43-128
            const encoder = new TextEncoder();
            const data = encoder.encode(verifier);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const challenge = btoa(String.fromCharCode(...hashArray)) // Base64 encode
                .replace(/\+/g, '-') // Convert '+' to '-'
                .replace(/\//g, '_') // Convert '/' to '_'
                .replace(/=+$/, ''); // Remove trailing '='

            return { verifier, challenge };
        }

        return {
            //Public methods
            async initiateGoogleLogin() {
                if (!isBrowser) return;

                patchState(store, () => {
                    return { isLoading: true, error: null }
                });

                try {
                    const { verifier, challenge } = await generatePkcePair();

                    // Store verifier in sessionStorage to persist across redirect
                    sessionStorage.setItem('pkce_code_verifier', verifier);

                    // Build Google OAuth URL
                    const googleAuthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
                    googleAuthUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID); // From Google Cloud Console
                    googleAuthUrl.searchParams.set('redirect_uri', 'http://localhost:4200/auth/callback'); // Must match console & Spring Boot config
                    googleAuthUrl.searchParams.set('response_type', 'code');
                    googleAuthUrl.searchParams.set('scope', 'openid email profile'); // Request minimal scopes
                    googleAuthUrl.searchParams.set('access_type', 'offline'); // To get a refresh token (handled by backend)
                    googleAuthUrl.searchParams.set('prompt', 'consent select_account'); // Force consent screen

                    // PKCE parameters
                    googleAuthUrl.searchParams.set('code_challenge', challenge);
                    googleAuthUrl.searchParams.set('code_challenge_method', 'S256');

                    window.location.href = googleAuthUrl.toString();
                } catch (error) {
                    console.error('Error generating PKCE or initiating login:', error);
                    patchState(store, () => {
                        return { isLoading: false, error: 'Error generating PKCE or initiating login' }
                    });
                }
            },

            loginSuccess(user: User, accessToken: string, expiresIn: number) {
                patchState(store, () => {
                    return {
                        user,
                        accessToken,
                        expiresIn,
                        isAuthenticated: true,
                        isLoading: false,
                        error: null,
                    }
                });

                if (isBrowser) {
                    localStorage.setItem(AUTH_KEY, JSON.stringify({
                       ACCESS_TOKEN_KEY: accessToken,
                       TOKEN_EXIPIRY_KEY: expiresIn,
                    })); // Storing YOUR internal token
                    sessionStorage.removeItem('pkce_code_verifier'); // Clean up PKCE verifier
                }
            },

            loginFailure(error: string) {
                patchState(store, () => {
                    return {
                        isLoading: false,
                        error,
                        isAuthenticated: false,
                    }
                });
                if (isBrowser) {
                    sessionStorage.removeItem('pkce_code_verifier'); // Clean up PKCE verifier on failure
                }
            },

            logout() {
                patchState(store, () => {
                    return {
                        user: null,
                        accessToken: null,
                        expiresIn: 0,
                        isAuthenticated: false,
                        isLoading: false,
                        error: null,
                    }
                });

                if (isBrowser) {
                    localStorage.removeItem(ACCESS_TOKEN_KEY);
                }
            },

            startLoading() {
                patchState(store, () => {
                    return { isLoading: true, error: null }
                });
            },

            // --- Private/Internal Methods ---
            _loadTokensFromStorage() {
                if (isBrowser) {
                    const auth = localStorage.getItem(AUTH_KEY);
                    if (auth) {
                        const { accessToken, expiresIn } = JSON.parse(auth);

                        // In a real app, you might decode the JWT locally to get user info
                        // and check expiration. Or make an API call to your backend /me endpoint.
                        patchState(store, () => {
                            return { accessToken, expiresIn, isAuthenticated: true }
                        });
                        // Optionally, if user is not fully populated, fetch from backend:
                        // inject(AuthService).fetchCurrentUser().subscribe();
                    }
                }
            },

            setUser(user: User) {
                patchState(store, () => {
                    return { user }
                });
            }
        }
    }),
    withHooks((store) => ({
        onInit() {
            store._loadTokensFromStorage();
          },
    }))
);