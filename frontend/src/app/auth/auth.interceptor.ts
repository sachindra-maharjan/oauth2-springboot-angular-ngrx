import { HttpEvent, HttpHandlerFn, HttpRequest, HttpInterceptorFn } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthStore } from './auth.store';
import { inject } from '@angular/core';

export const authInterceptor: HttpInterceptorFn = (req: 
    HttpRequest<any>, 
    next: HttpHandlerFn): Observable<HttpEvent<any>> => {

    const authStore = inject(AuthStore);
    const accessToken = authStore.accessToken() // Get the current access token (your backend's JWT)

    console.log('Auth Interceptor:', {
        url: req.url,
        method: req.method,
        accessToken: accessToken, // Log if token is present
        headers: req.headers.keys(),
    });
    
    // Only add header for requests to your backend's API
    if (accessToken && req.url.startsWith('http://localhost:8080/api')) {
        const clonedReq = req.clone({
            headers: req.headers.set('Authorization', `Bearer ${accessToken}`),
        });
        return next(clonedReq);
    }
    
    return next(req);
}   

