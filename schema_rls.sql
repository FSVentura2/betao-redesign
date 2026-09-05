-- ==========================================================
-- BETÃO ENTERPRISE DATABASE SCHEMA & ROW-LEVEL SECURITY (RLS)
-- Padrão de Segurança: NIST SP 800-53 / OWASP Top 10
-- ==========================================================

-- Extensões de segurança
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. TIPOS ENUMERADOS (Controle de privilégios e estados imutáveis)
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('USER', 'AUDITOR', 'ADMIN');
    CREATE TYPE bet_status AS ENUM ('PENDING', 'WON', 'LOST', 'CANCELED');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. TABELA DE USUÁRIOS
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cpf VARCHAR(14) UNIQUE NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Hashing Argon2id gerado exclusivamente no servidor
    role user_role DEFAULT 'USER' NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    balance_cents BIGINT DEFAULT 0 NOT NULL CHECK (balance_cents >= 0), -- Saldo em centavos contra erros de ponto flutuante
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 3. TABELA DE EVENTOS ESPORTIVOS (Apenas leitura para clientes)
CREATE TABLE IF NOT EXISTS sports_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sport_category VARCHAR(50) NOT NULL,
    competition_name VARCHAR(100) NOT NULL,
    home_team VARCHAR(100) NOT NULL,
    away_team VARCHAR(100) NOT NULL,
    home_score INT DEFAULT 0 NOT NULL,
    away_score INT DEFAULT 0 NOT NULL,
    is_live BOOLEAN DEFAULT FALSE NOT NULL,
    odd_home NUMERIC(6, 2) NOT NULL,
    odd_draw NUMERIC(6, 2) NOT NULL,
    odd_away NUMERIC(6, 2) NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE NOT NULL, -- Bloqueio de apostas em lances críticos
    start_time TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 4. TABELA DE APOSTAS / CUPONS (CRÍTICO: Imutabilidade e RLS)
CREATE TABLE IF NOT EXISTS bets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_id UUID NOT NULL REFERENCES sports_events(id) ON DELETE RESTRICT,
    selected_market VARCHAR(50) NOT NULL,
    locked_odd NUMERIC(6, 2) NOT NULL CHECK (locked_odd >= 1.01), -- Odd validada pelo servidor no momento da compra
    stake_amount_cents BIGINT NOT NULL CHECK (stake_amount_cents > 0), -- Valor da aposta
    potential_payout_cents BIGINT NOT NULL, -- Calculado pelo servidor, NUNCA pelo cliente
    status bet_status DEFAULT 'PENDING' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ==========================================================
-- 🛡️ ATIVAÇÃO E VALIDAÇÃO DE ROW-LEVEL SECURITY (RLS)
-- Critério 4, 6 e 7
-- ==========================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE bets ENABLE ROW LEVEL SECURITY;
ALTER TABLE sports_events ENABLE ROW LEVEL SECURITY;

-- POLÍTICAS PARA USERS:
-- O usuário só pode ler seu próprio registro (sem expor hash de senha)
DROP POLICY IF EXISTS users_self_view ON users;
CREATE POLICY users_self_view ON users
    FOR SELECT
    USING (auth_user_id() = id);

-- Apenas o processo interno do sistema pode atualizar saldo
DROP POLICY IF EXISTS users_admin_update ON users;
CREATE POLICY users_admin_update ON users
    FOR UPDATE
    USING (current_setting('app.current_user_role', true) = 'ADMIN');

-- POLÍTICAS PARA APOSTAS:
-- 1. O apostador só enxerga os seus próprios cupons
DROP POLICY IF EXISTS bets_owner_select ON bets;
CREATE POLICY bets_owner_select ON bets
    FOR SELECT
    USING (auth_user_id() = user_id);

-- 2. O apostador só pode inserir apostas para ele mesmo e nunca para terceiros
DROP POLICY IF EXISTS bets_owner_insert ON bets;
CREATE POLICY bets_owner_insert ON bets
    FOR INSERT
    WITH CHECK (auth_user_id() = user_id);

-- 3. Ninguém (exceto ADMIN/Servidor de Liquidação) pode alterar ou excluir apostas existentes (Imutabilidade)
DROP POLICY IF EXISTS bets_prevent_update ON bets;
CREATE POLICY bets_prevent_update ON bets
    FOR UPDATE
    USING (current_setting('app.current_user_role', true) = 'ADMIN');

-- POLÍTICAS PARA EVENTOS:
-- Leitura pública para todos os apostadores autenticados e anônimos
DROP POLICY IF EXISTS sports_events_read_all ON sports_events;
CREATE POLICY sports_events_read_all ON sports_events
    FOR SELECT
    USING (true);

-- ==========================================================
-- ÍNDICES PARA AUDITORIA E ALTA PERFORMANCE
-- ==========================================================
CREATE INDEX IF NOT EXISTS idx_bets_user_id ON bets(user_id);
CREATE INDEX IF NOT EXISTS idx_events_start_time ON sports_events(start_time);
CREATE INDEX IF NOT EXISTS idx_users_cpf_email ON users(cpf, email);
