CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    uuid UUID UNIQUE NOT NULL,
    roles VARCHAR(255) NOT NULL DEFAULT 'user',
    mail VARCHAR(150) UNIQUE NOT NULL,
    password TEXT NOT NULL DEFAULT 'nope',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES Users(id) ON DELETE CASCADE,
    user_uuid UUID REFERENCES Users(uuid) ON DELETE CASCADE,
    device VARCHAR(255) NOT NULL,  -- Ex: "iPhone", "Windows", "Chrome"
    ip_address VARCHAR(45),        -- Stocke l'IP de l'utilisateur
    user_agent TEXT,               -- Stocke l'User-Agent du navigateur ou de l'app
    refresh_token TEXT UNIQUE NOT NULL, -- Stocke le Refresh Token unique
    uuid UUID UNIQUE NOT NULL,
    disponibility VARCHAR(255) NOT NULL DEFAULT 'valid',
    expires_at TIMESTAMPTZ NOT NULL,  -- Expiration du token
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
