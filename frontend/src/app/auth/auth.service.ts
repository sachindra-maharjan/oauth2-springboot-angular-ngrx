import { HttpClient } from '@angular/common/http';
import { inject, Injectable } from '@angular/core';
import { AuthStore } from './auth.store';
import { User } from './auth.model';
import { environment } from '../environment';
import { catchError, Observable, tap, of, firstValueFrom } from 'rxjs';
import { Router } from '@angular/router';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private readonly http = inject(HttpClient);
  private readonly authStore = inject(AuthStore);
  private readonly router = inject(Router)

  readonly user = this.authStore.user;
  readonly isAuthenticated = this.authStore.isAuthenticated;
  readonly isLoading = this.authStore.isLoading;
  readonly authError = this.authStore.error;

  private readonly backendAuthUrl = environment.BACKEND_AUTH_URL;

  loginWithGoogle(): void {
    this.authStore.initiateGoogleLogin();
  }

  async handleGoogleLoginCallback(authCode: string) {
    const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
    if (!codeVerifier) {
      this.authStore.loginFailure('Code verifier not found');
      this.router.navigate(['/login']);
      return;
    }

     this.authStore.startLoading();

      try {
        const response = await firstValueFrom(this.http.post<{user: User, accessToken: string, expiresIn: number }>(
          `${this.backendAuthUrl}/google/callback`, { authCode, codeVerifier })
          .pipe(
            tap((res) => {
              console.log('Backend callback response', res);
              this.authStore.loginSuccess(res.user, res.accessToken, res.expiresIn);
            }),
            catchError((err) => {
              const errorMessage = err.error?.message || 'Failed to login with Google';
              this.authStore.loginFailure(errorMessage);
              return err;
            })
          )
        );

        console.log('Login successful', response);
        this.router.navigate(['/dashboard']); // Redirect to dashboard on success
      } catch (error) {
        console.error('Login callback error', error);
        this.router.navigate(['/login']);
      }
  }

  logout(): void {
    this.authStore.logout();
    this.router.navigate(['/login']);
    // Invalidate JWT/session if available in the backend
    // this.http.post(`${this.backendAuthUrl}/logout`, {}).subscribe({
    //   next: () => console.log('Logged out successfully'),
    //   error: (err) => console.error('Logout error', err)
    // });
  }

  loginFailure(errorMessage: string): void {
    this.authStore.loginFailure(errorMessage);
  }

  fetchUserProfile(): Observable<User | null> {
    if (!this.isAuthenticated()) {
      return of(null);
    }

    return this.http.get<User>(`${this.backendAuthUrl}/me`).pipe(
      tap(user => {
        this.authStore.setUser(user);
      }),
      catchError(error => {
        console.error('Failed to fetch user profile', error);
        if (error.status === 401 || error.status === 403) {
          this.logout()
        }
        return of(null);
      })
    );
  }

}
