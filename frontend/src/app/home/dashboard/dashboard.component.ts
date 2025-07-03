import { CommonModule } from '@angular/common';
import { Component, inject, OnInit } from '@angular/core';
import { AuthService } from '../../auth/auth.service';
import { HttpClient } from '@angular/common/http';


@Component({
  selector: 'app-dashboard',
  imports: [CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit{
  authService = inject(AuthService);
  private http = inject(HttpClient);
  apiResponse: string | null = null;
  apiError: string | null = null;

  ngOnInit(): void {
    // Optionally fetch full user info if not already in store or if you need fresh data
    if (!this.authService.user()) {
        this.authService.fetchUserProfile().subscribe();
    }
  }

  testProtectedApi(): void {
    this.apiResponse = null;
    this.apiError = null;
    this.http.get('http://localhost:8080/api/auth/me').subscribe({
      next: (data: any) => {
        this.apiResponse = 'Successfully fetched protected data: ' + JSON.stringify(data);
      },
      error: (err) => {
        this.apiError = 'Failed to fetch protected data. Status: ' + err.status;
        console.error('API call error:', err);
      },
    });
  }
}
