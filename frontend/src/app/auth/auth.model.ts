export interface User {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    picture: string;
}


export interface AuthState {
    user: User | null;
    token: string | null;
    expiresIn: number;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
}

export const initialAuthState: AuthState = {
    user: null,
    token: null,
    expiresIn: 0,
    isAuthenticated: false,
    isLoading: false,
    error: null,
}
