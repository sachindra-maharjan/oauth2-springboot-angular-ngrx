import { CommonModule } from '@angular/common';
import { Component, inject, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';
import { AuthService } from '../../auth/auth.service';

@Component({
  selector: 'app-auth-callback',
  imports: [CommonModule],
  templateUrl: './auth-callback.component.html',
  styleUrl: './auth-callback.component.css'
})
export class AuthCallbackComponent implements OnInit{

  private route = inject(ActivatedRoute);
  protected authService = inject(AuthService);


  ngOnInit(): void {
    this.route.queryParams.subscribe((params: Params) => {
      const code = params['code'];
      const error = params['error'];

      if (code) {
        this.authService.handleGoogleLoginCallback(code);
      } else if (error) {
        const errorMessage = params['error_description'] || 'Google authentication denied or failed.';
        this.authService.loginFailure(errorMessage);
      } else {
        this.authService.loginFailure('No authorization code received from Google.');
      }
    });
  }

}
