import { HttpEvent, HttpHandlerFn, HttpRequest, HttpInterceptorFn } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthStore } from './auth.store';
import { inject } from '@angular/core';

export const authInterceptor: HttpInterceptorFn = (req: 
    HttpRequest<any>, 
    next: HttpHandlerFn): Observable<HttpEvent<any>> => {

    const authStore = inject(AuthStore);
    const accessToken = authStore.token() // Get the current access token (your backend's JWT)
    
    // Only add header for requests to your backend's API
    if (accessToken && req.url.startsWith('http://localhost:8080/api')) {
        const clonedReq = req.clone({
            headers: req.headers.set('Authorization', `Bearer ${accessToken}`),
        });
        return next(clonedReq);
    }
    
    return next(req);
}   

