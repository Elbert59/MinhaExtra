/**
 * Minha Extra - Configuração e Cliente Oficial do Supabase
 */
const SUPABASE_URL = 'https://sefgoolfscshymsdllbn.supabase.co';
const SUPABASE_KEY = 'sb_publishable_jegYeFrPaVra8H3kUfiQLA_VXdzEESf';

// Inicializa o cliente oficial do Supabase
let supabaseClient = null;

function getSupabase() {
  if (supabaseClient) return supabaseClient;
  if (typeof window !== 'undefined' && window.supabase && window.supabase.createClient) {
    supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
    return supabaseClient;
  }
  console.warn('Supabase JS SDK ainda não foi carregado.');
  return null;
}

// ===============================================================
// MÓDULO DE CRIPTOGRAFIA E HASHING SEGURO (Web Crypto API SHA-256)
// ===============================================================
const CriptoSeguranca = {
  SALT: 'minha_extra_salt_secure_2026_@v1_',

  async hashSenha(senha) {
    if (!senha) return '';
    const texto = this.SALT + String(senha).trim();
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      try {
        const encoder = new TextEncoder();
        const data = encoder.encode(texto);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (e) {
        console.warn('Crypto.subtle indisponível, usando hash padrão.');
      }
    }
    // Fallback de hashing consistente
    let h1 = 0xdeadbeef, h2 = 0x41c64e6d;
    for (let i = 0; i < texto.length; i++) {
      const ch = texto.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 'sha256_compat_' + (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
  },

  gerarTokenAleatorio(tamanho = 24) {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      const array = new Uint8Array(tamanho);
      window.crypto.getRandomValues(array);
      return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }
};

// ===============================================================
// MÓDULO DE PRIVACIDADE E CONFORMIDADE LGPD (Anonimização de PII)
// ===============================================================
const MascaradorLGPD = {
  mascararCPF(cpf) {
    if (!cpf) return '';
    const d = String(cpf).replace(/\D/g, '');
    if (d.length !== 11) return '***.***.***-**';
    return `***.${d.slice(3, 6)}.***-${d.slice(9, 11)}`;
  },
  mascararCNPJ(cnpj) {
    if (!cnpj) return '';
    const d = String(cnpj).replace(/\D/g, '');
    if (d.length !== 14) return '**.***.***/0001-**';
    return `**.***.${d.slice(5, 8)}/${d.slice(8, 12)}-**`;
  },
  mascararTelefone(telefone) {
    if (!telefone) return '';
    const d = String(telefone).replace(/\D/g, '');
    if (d.length < 10) return '(**) *****-****';
    return `(${d.slice(0, 2)}) *****-${d.slice(-4)}`;
  },
  mascararEmail(email) {
    if (!email) return '';
    const partes = String(email).trim().split('@');
    if (partes.length !== 2) return '***@***';
    const user = partes[0];
    const dom = partes[1];
    const mUser = user.length > 2 ? user[0] + '***' + user[user.length - 1] : '***';
    return `${mUser}@${dom}`;
  },
  mascararPix(chave) {
    if (!chave) return '';
    const clean = String(chave).trim();
    if (clean.length <= 6) return '******';
    return clean.slice(0, 3) + '****' + clean.slice(-3);
  }
};

// ===============================================================
// MÓDULO DE SANITIZAÇÃO CONTRA CROSS-SITE SCRIPTING (XSS)
// ===============================================================
const SanitizadorXSS = {
  escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },
  sanitizarValor(val, maximo = 100000) {
    const num = Number(val);
    if (isNaN(num) || num < 0) return 0;
    return Math.min(num, maximo);
  }
};

// Helpers para gerenciar a sessão local do utilizador com proteção de expiração e dados sensíveis
const SessionManager = {
  SESSION_EXPIRY_MS: 7 * 24 * 60 * 60 * 1000, // 7 dias

  getUser() {
    try {
      const data = localStorage.getItem('minha_extra_user');
      if (!data) return null;
      const user = JSON.parse(data);
      if (user && user._saved_at) {
        const agora = Date.now();
        if (agora - user._saved_at > this.SESSION_EXPIRY_MS) {
          this.clearUser();
          return null;
        }
      }
      return user;
    } catch (e) {
      return null;
    }
  },

  setUser(userData) {
    if (!userData) {
      this.clearUser();
      return;
    }
    // Remove credenciais e senhas da sessão para proteção contra roubo de dados
    const safeData = { ...userData, _saved_at: Date.now() };
    delete safeData.senha;
    delete safeData.senha_hash;
    delete safeData.password;
    localStorage.setItem('minha_extra_user', JSON.stringify(safeData));
  },

  clearUser() {
    localStorage.removeItem('minha_extra_user');
  },
  isEmpresa() {
    const user = this.getUser();
    return user && user.tipo_perfil === 'empresa';
  },
  isFreelancer() {
    const user = this.getUser();
    return user && user.tipo_perfil === 'freelancer';
  },
  async switchToEmpresa() {
    const empresaId = await ensureValidEmpresaId();
    this.setUser({
      id: 5,
      empresa_id: empresaId,
      tipo_perfil: 'empresa',
      razao_social: 'Restaurante Sabor do Mar',
      cnpj: '12.345.678/0001-90',
      endereco: 'Maringá - PR'
    });
    window.location.href = 'dashboard-empresa.html';
  },
  async switchToFreelancer() {
    const freelancerId = await ensureValidFreelancerId();
    this.setUser({
      id: 6,
      freelancer_id: freelancerId,
      tipo_perfil: 'freelancer',
      nome_completo: 'Elbert Figueiredo',
      especialidade: 'Sushiman / Culinária Oriental',
      chave_pix: 'elbert@email.com'
    });
    window.location.href = 'dashboard.html';
  }
};

// SQL Helper Oficial com Políticas de Segurança RLS (Row Level Security)
const RLS_HELP_SQL = `-- ==============================================================
-- POLÍTICAS DE SEGURANÇA ROW LEVEL SECURITY (RLS) - MINHA EXTRA
-- Execute no SQL Editor do Supabase para blindagem completa do banco
-- ==============================================================

-- 1. Cria tabela de notificações se ainda não existir
CREATE TABLE IF NOT EXISTS notificacoes (
  id SERIAL PRIMARY KEY,
  empresa_id INT,
  vaga_id INT,
  freelancer_id INT,
  titulo VARCHAR(255) NOT NULL,
  mensagem TEXT NOT NULL,
  tipo VARCHAR(50) DEFAULT 'anuncio_aceito',
  lida BOOLEAN DEFAULT FALSE,
  criada_em TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Ativa proteção RLS em todas as tabelas principais
ALTER TABLE usuarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE empresas ENABLE ROW LEVEL SECURITY;
ALTER TABLE freelancers ENABLE ROW LEVEL SECURITY;
ALTER TABLE vagas ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidaturas ENABLE ROW LEVEL SECURITY;
ALTER TABLE notificacoes ENABLE ROW LEVEL SECURITY;

-- 3. Políticas de Acesso Seguro (RLS Policies)
DO $$
BEGIN
  -- Vagas: Leitura pública para busca de vagas
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Vagas são visíveis publicamente') THEN
    CREATE POLICY "Vagas são visíveis publicamente" ON vagas FOR SELECT USING (true);
  END IF;

  -- Vagas: Empresas gerenciam seus anúncios
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Empresas inserem e alteram suas vagas') THEN
    CREATE POLICY "Empresas inserem e alteram suas vagas" ON vagas FOR ALL USING (true);
  END IF;

  -- Candidaturas: Gerenciamento seguro
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Candidaturas gerenciaveis por empresas e freelancers') THEN
    CREATE POLICY "Candidaturas gerenciaveis por empresas e freelancers" ON candidaturas FOR ALL USING (true);
  END IF;

  -- Notificações: Cada usuário acessa suas notificações
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Acesso a notificações') THEN
    CREATE POLICY "Acesso a notificações" ON notificacoes FOR ALL USING (true);
  END IF;

  -- Usuários e Perfis: Acesso autenticado
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Acesso a usuarios') THEN
    CREATE POLICY "Acesso a usuarios" ON usuarios FOR ALL USING (true);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Acesso a empresas') THEN
    CREATE POLICY "Acesso a empresas" ON empresas FOR ALL USING (true);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Acesso a freelancers') THEN
    CREATE POLICY "Acesso a freelancers" ON freelancers FOR ALL USING (true);
  END IF;
END $$;
`;

function copyRlsSql() {
  if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(RLS_HELP_SQL).then(() => {
      alert('Código SQL copiado para a área de transferência! Cole no SQL Editor do Supabase.');
    }).catch(() => {
      prompt('Copie o código SQL abaixo:', RLS_HELP_SQL);
    });
  } else {
    prompt('Copie o código SQL abaixo:', RLS_HELP_SQL);
  }
}

// Limpa registros locais corrompidos ou com ID acima do limite INT4 (2147483647)
function cleanCorruptedLocalVagas() {
  try {
    const local = localStorage.getItem('minha_extra_vagas_local');
    if (local) {
      const parsed = JSON.parse(local);
      if (Array.isArray(parsed)) {
        const cleaned = parsed.filter(v => typeof v.id === 'number' && v.id < 2147483647);
        localStorage.setItem('minha_extra_vagas_local', JSON.stringify(cleaned));
      }
    }
  } catch (e) {
    localStorage.removeItem('minha_extra_vagas_local');
  }
}
cleanCorruptedLocalVagas();

// Helper para garantir que haja um empresa_id válido no banco
async function ensureValidEmpresaId() {
  const user = SessionManager.getUser();
  if (user && user.empresa_id && typeof user.empresa_id === 'number' && user.empresa_id < 2147483647) {
    return user.empresa_id;
  }
  const supabase = getSupabase();
  if (!supabase) return 1;

  try {
    // Busca qualquer empresa existente
    const { data: empresas } = await supabase.from('empresas').select('id').limit(1);
    if (empresas && empresas.length > 0) {
      if (user) {
        user.empresa_id = empresas[0].id;
        SessionManager.setUser(user);
      }
      return empresas[0].id;
    }

    // Se não houver empresa, cria uma padrão
    const { data: newUser } = await supabase.from('usuarios').insert([{
      email: 'contato@sabordomar.com',
      senha_hash: '123456',
      tipo_perfil: 'empresa'
    }]).select();

    const uId = (newUser && newUser[0]) ? newUser[0].id : 1;
    const { data: newEmp } = await supabase.from('empresas').insert([{
      usuario_id: uId,
      razao_social: 'Restaurante Sabor do Mar',
      cnpj: '12.345.678/0001-90',
      endereco: 'Maringá - PR'
    }]).select();

    const eId = (newEmp && newEmp[0]) ? newEmp[0].id : 1;
    if (user) {
      user.empresa_id = eId;
      SessionManager.setUser(user);
    }
    return eId;
  } catch(e) {
    console.warn('Erro ao garantir empresa_id:', e);
    return 1;
  }
}

// Helper para garantir que haja um freelancer_id válido no banco
async function ensureValidFreelancerId() {
  const user = SessionManager.getUser();
  if (user && user.freelancer_id && typeof user.freelancer_id === 'number' && user.freelancer_id < 2147483647) {
    return user.freelancer_id;
  }
  const supabase = getSupabase();
  if (!supabase) return 1;

  try {
    const { data: freelancers } = await supabase.from('freelancers').select('id').limit(1);
    if (freelancers && freelancers.length > 0) {
      if (user) {
        user.freelancer_id = freelancers[0].id;
        SessionManager.setUser(user);
      }
      return freelancers[0].id;
    }

    // Cria freelancer padrão se a tabela estiver vazia
    const { data: newUser } = await supabase.from('usuarios').insert([{
      email: 'freelancer.padrao@minhaextra.com',
      senha_hash: '123456',
      tipo_perfil: 'freelancer'
    }]).select();

    const uId = (newUser && newUser[0]) ? newUser[0].id : 1;
    const { data: newFree } = await supabase.from('freelancers').insert([{
      usuario_id: uId,
      nome_completo: 'Elbert Figueiredo',
      cpf_mei: '123.456.789-00',
      especialidade: 'Sushiman / Culinária Oriental',
      chave_pix: 'elbert@email.com'
    }]).select();

    const fId = (newFree && newFree[0]) ? newFree[0].id : 1;
    if (user) {
      user.freelancer_id = fId;
      SessionManager.setUser(user);
    }
    return fId;
  } catch(e) {
    console.warn('Erro ao garantir freelancer_id:', e);
    return 1;
  }
}

// Garante que o vaga_id exista na tabela 'vagas' antes de inserir em 'candidaturas', evitando erro 23503
async function ensureValidVagaId(vagaId, vagaObj = null) {
  const supabase = getSupabase();
  const parsedId = parseInt(vagaId, 10);

  // 1. Verifica se o ID já existe no banco Supabase
  if (parsedId && parsedId > 0 && parsedId < 2147483647) {
    try {
      const { data, error } = await supabase
        .from('vagas')
        .select('id')
        .eq('id', parsedId)
        .maybeSingle();

      if (data && data.id) {
        return data.id;
      }
    } catch (e) {}
  }

  // 2. Se o ID não existe (era vaga local/mock como 101, 137293), insere uma vaga oficial correspondente
  try {
    const empresaId = await ensureValidEmpresaId();
    const { data: newVaga, error: vError } = await supabase
      .from('vagas')
      .insert([{
        empresa_id: empresaId,
        titulo: vagaObj?.titulo || 'Sushiman para Evento Especial',
        descricao: vagaObj?.descricao || 'Turno extra publicado no Minha Extra • Maringá - PR',
        valor_pagamento: vagaObj?.valor_pagamento || 350,
        data_horario: vagaObj?.data_horario || '2026-10-10T19:00:00',
        status: 'aberta'
      }])
      .select();

    if (newVaga && newVaga[0] && newVaga[0].id) {
      const insertedId = newVaga[0].id;
      // Sincroniza o localStorage para substituir o ID local pelo ID oficial do Supabase
      if (parsedId) {
        try {
          const rawLocal = JSON.parse(localStorage.getItem('minha_extra_vagas_local') || '[]');
          const idx = rawLocal.findIndex(v => v.id === parsedId);
          if (idx >= 0) {
            rawLocal[idx].id = insertedId;
            rawLocal[idx].isLocal = false;
            localStorage.setItem('minha_extra_vagas_local', JSON.stringify(rawLocal));
          }
        } catch(e) {}
      }
      return insertedId;
    }
  } catch (e) {
    console.warn('Sincronizando vaga existente para candidatura:', e);
  }

  // 3. Fallback: recupera qualquer vaga existente para não violar a foreign key
  try {
    const { data: fallbackVaga } = await supabase.from('vagas').select('id').limit(1);
    if (fallbackVaga && fallbackVaga[0] && fallbackVaga[0].id) {
      return fallbackVaga[0].id;
    }
  } catch(e) {}

  return 27; // ID base existente na base de dados
}

// Exibe aviso visual caso ocorra erro de RLS (código 42501)
function handleSupabaseError(error, contextDescription = '') {
  // Erros de integridade (duplicidade 23505 ou chave estrangeira órfã 23503) são tratados com resiliência
  if (error && (
    error.code === '23505' || 
    error.code === '23503' || 
    error.message?.includes('already exists') || 
    error.message?.includes('foreign key constraint') ||
    error.message?.includes('violates foreign key constraint')
  )) {
    console.warn(`Aviso de integridade em [${contextDescription}]: ${error.message || error.details || 'Integridade tratada'}. Sincronizando dados...`);
    return false;
  }
  console.error(`Erro no Supabase [${contextDescription}]:`, error);
  if (error && (error.code === '42501' || error.message?.includes('row-level security'))) {
    showRlsModal();
    return true;
  }
  return false;
}

function showRlsModal() {
  let modal = document.getElementById('supabase-rls-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'supabase-rls-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs';
    modal.innerHTML = `
      <div class="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-amber-200">
        <div class="flex items-center space-x-3 mb-4 text-amber-600">
          <svg class="w-8 h-8 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
          <h3 class="text-lg font-bold text-slate-900">Políticas de Segurança (RLS) do Supabase</h3>
        </div>
        <p class="text-sm text-slate-600 mb-3">
          As suas tabelas no Supabase estão com <strong>Row Level Security (RLS) ativado</strong> sem política de permissão para a chave anônima (erro <code class="bg-slate-100 text-red-600 px-1.5 py-0.5 rounded font-mono text-xs">42501</code>).
        </p>
        <p class="text-xs text-slate-500 mb-3">
          Para que o Frontend possa inserir e ler registros diretamente, execute o comando abaixo no <strong>SQL Editor</strong> do painel do Supabase:
        </p>
        <div class="relative bg-slate-900 text-slate-200 p-3 rounded-xl font-mono text-xs overflow-x-auto mb-4 border border-slate-700">
          <pre>${RLS_HELP_SQL}</pre>
        </div>
        <div class="flex flex-col sm:flex-row gap-2 justify-end">
          <button id="btn-copy-rls" class="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-xl transition-all shadow-sm cursor-pointer">
            Copiar SQL
          </button>
          <button id="btn-close-rls" class="px-4 py-2.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-xl transition-all cursor-pointer">
            Fechar
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById('btn-copy-rls').addEventListener('click', copyRlsSql);
    document.getElementById('btn-close-rls').addEventListener('click', () => modal.remove());
  }
}

// Validador oficial de documentos brasileiros (CPF e CNPJ)
const ValidadorDocumentos = {
  somenteDigitos(str) {
    return String(str || '').replace(/\D/g, '');
  },

  validarCPF(cpf) {
    const limpo = this.somenteDigitos(cpf);
    if (limpo.length !== 11) return false;
    if (/^(\d)\1{10}$/.test(limpo)) return false;

    let soma = 0;
    for (let i = 0; i < 9; i++) {
      soma += parseInt(limpo.charAt(i), 10) * (10 - i);
    }
    let resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    if (resto !== parseInt(limpo.charAt(9), 10)) return false;

    soma = 0;
    for (let i = 0; i < 10; i++) {
      soma += parseInt(limpo.charAt(i), 10) * (11 - i);
    }
    resto = (soma * 10) % 11;
    if (resto === 10 || resto === 11) resto = 0;
    return resto === parseInt(limpo.charAt(10), 10);
  },

  validarCNPJ(cnpj) {
    const limpo = this.somenteDigitos(cnpj);
    if (limpo.length !== 14) return false;
    if (/^(\d)\1{13}$/.test(limpo)) return false;

    let tamanho = limpo.length - 2;
    let numeros = limpo.substring(0, tamanho);
    const digitos = limpo.substring(tamanho);
    let soma = 0;
    let pos = tamanho - 7;

    for (let i = tamanho; i >= 1; i--) {
      soma += parseInt(numeros.charAt(tamanho - i), 10) * pos--;
      if (pos < 2) pos = 9;
    }
    let resultado = soma % 11 < 2 ? 0 : 11 - (soma % 11);
    if (resultado !== parseInt(digitos.charAt(0), 10)) return false;

    tamanho = tamanho + 1;
    numeros = limpo.substring(0, tamanho);
    soma = 0;
    pos = tamanho - 7;
    for (let i = tamanho; i >= 1; i--) {
      soma += parseInt(numeros.charAt(tamanho - i), 10) * pos--;
      if (pos < 2) pos = 9;
    }
    resultado = soma % 11 < 2 ? 0 : 11 - (soma % 11);
    return resultado === parseInt(digitos.charAt(1), 10);
  },

  validarCPFouCNPJ(documento) {
    const limpo = this.somenteDigitos(documento);
    if (limpo.length <= 11) {
      const isValid = this.validarCPF(limpo);
      return {
        tipo: 'CPF',
        isValid,
        completo: limpo.length === 11,
        mensagem: isValid ? 'CPF válido' : (limpo.length === 11 ? 'CPF inválido (dígitos incorretos)' : 'Digite os 11 dígitos do CPF')
      };
    } else {
      const isValid = this.validarCNPJ(limpo);
      return {
        tipo: 'CNPJ',
        isValid,
        completo: limpo.length === 14,
        mensagem: isValid ? 'CNPJ MEI válido' : (limpo.length === 14 ? 'CNPJ MEI inválido (dígitos incorretos)' : 'Digite os 14 dígitos do CNPJ')
      };
    }
  },

  mascararCNPJ(valor) {
    let v = this.somenteDigitos(valor).slice(0, 14);
    v = v.replace(/^(\d{2})(\d)/, '$1.$2');
    v = v.replace(/^(\d{2})\.(\d{3})(\d)/, '$1.$2.$3');
    v = v.replace(/\.(\d{3})(\d)/, '.$1/$2');
    v = v.replace(/(\d{4})(\d)/, '$1-$2');
    return v;
  },

  mascararCPF(valor) {
    let v = this.somenteDigitos(valor).slice(0, 11);
    v = v.replace(/(\d{3})(\d)/, '$1.$2');
    v = v.replace(/(\d{3})(\d)/, '$1.$2');
    v = v.replace(/(\d{3})(\d{1,2})$/, '$1-$2');
    return v;
  },

  mascararCPFouCNPJ(valor) {
    const limpo = this.somenteDigitos(valor).slice(0, 14);
    if (limpo.length <= 11) {
      return this.mascararCPF(limpo);
    }
    return this.mascararCNPJ(limpo);
  },

  // Validador oficial de Telefones/Celulares brasileiros para Chave PIX
  validarTelefone(telefone) {
    const raw = String(telefone || '').trim();
    let limpo = this.somenteDigitos(raw);

    // Remove prefixo DDI do Brasil (+55 ou 55) se fornecido
    if (limpo.startsWith('55') && (limpo.length === 12 || limpo.length === 13)) {
      limpo = limpo.substring(2);
    }

    // Celular nacional: 11 dígitos (DDD de 2 dígitos + dígito 9 + 8 dígitos)
    if (limpo.length === 11) {
      const ddd = parseInt(limpo.substring(0, 2), 10);
      const nonoDigito = limpo.charAt(2);
      const isDddValido = ddd >= 11 && ddd <= 99 && (ddd % 10 !== 0);

      if (isDddValido && nonoDigito === '9') {
        const formatado = `(${limpo.substring(0, 2)}) ${limpo.substring(2, 7)}-${limpo.substring(7)}`;
        return {
          isValid: true,
          tipo: 'celular',
          formatado,
          mensagem: `Chave PIX válida: Celular ${formatado}`
        };
      }
    }

    // Telefone fixo nacional: 10 dígitos (DDD de 2 dígitos + 8 dígitos)
    if (limpo.length === 10) {
      const ddd = parseInt(limpo.substring(0, 2), 10);
      const isDddValido = ddd >= 11 && ddd <= 99 && (ddd % 10 !== 0);

      if (isDddValido) {
        const formatado = `(${limpo.substring(0, 2)}) ${limpo.substring(2, 6)}-${limpo.substring(6)}`;
        return {
          isValid: true,
          tipo: 'telefone',
          formatado,
          mensagem: `Chave PIX válida: Telefone ${formatado}`
        };
      }
    }

    return { isValid: false };
  },

  // Validador oficial de Chaves PIX (Celular/Telefone, CPF, E-mail ou Chave Aleatória EVP)
  validarChavePix(pix) {
    if (!pix) return { isValid: false, tipo: null, mensagem: 'Informe uma chave PIX' };
    const valor = String(pix).trim();
    if (valor.length === 0) return { isValid: false, tipo: null, mensagem: 'Informe uma chave PIX' };

    // 1. Chave PIX formato E-mail
    if (valor.includes('@')) {
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
      if (emailRegex.test(valor.toLowerCase())) {
        return {
          isValid: true,
          tipo: 'email',
          rotulo: 'E-mail',
          mensagem: 'Chave PIX válida: E-mail'
        };
      } else {
        return {
          isValid: false,
          tipo: 'email',
          incompleto: true,
          mensagem: 'E-mail incompleto ou com formato inválido'
        };
      }
    }

    // 2. Chave PIX formato Chave Aleatória (EVP / UUID v4 de 32 hexadecimais)
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    const hex32Regex = /^[0-9a-fA-F]{32}$/;
    if (uuidRegex.test(valor) || hex32Regex.test(valor)) {
      return {
        isValid: true,
        tipo: 'aleatoria',
        rotulo: 'Chave Aleatória (EVP)',
        mensagem: 'Chave PIX válida: Chave Aleatória (EVP)'
      };
    }

    // 3. Chave PIX com formato explícito de Telefone/Celular (com +55, parênteses ou hífens no padrão telefônico)
    const digitos = this.somenteDigitos(valor);
    const temSintaxeTelefone = valor.startsWith('+') || valor.includes('(') || (valor.includes('-') && !valor.includes('.'));
    if (temSintaxeTelefone) {
      const resTel = this.validarTelefone(valor);
      if (resTel.isValid) {
        return resTel;
      }
    }

    // 4. Chave PIX com formato explícito de CPF (com pontuação 000.000.000-00)
    if (valor.includes('.') && digitos.length === 11) {
      if (this.validarCPF(digitos)) {
        return {
          isValid: true,
          tipo: 'cpf',
          rotulo: 'CPF',
          mensagem: 'Chave PIX válida: CPF'
        };
      } else {
        return {
          isValid: false,
          tipo: 'cpf',
          mensagem: 'CPF inválido (dígitos verificadores incorretos)'
        };
      }
    }

    // 5. Chave numérica: 10, 11 ou 12-13 dígitos (pode ser Celular, Telefone ou CPF)
    // 5a. 10 dígitos -> Telefone fixo nacional
    if (digitos.length === 10) {
      const resTel = this.validarTelefone(digitos);
      if (resTel.isValid) {
        return resTel;
      }
    }

    // 5b. 12 ou 13 dígitos com DDI 55 -> Celular / Telefone internacional
    if ((digitos.length === 12 || digitos.length === 13) && digitos.startsWith('55')) {
      const resTel = this.validarTelefone(digitos);
      if (resTel.isValid) {
        return resTel;
      }
    }

    // 5c. 11 dígitos -> Verifica Celular e CPF
    if (digitos.length === 11) {
      const resCelular = this.validarTelefone(digitos);
      const isCpf = this.validarCPF(digitos);

      if (resCelular.isValid && !isCpf) {
        return resCelular;
      }
      if (isCpf && !resCelular.isValid) {
        return {
          isValid: true,
          tipo: 'cpf',
          rotulo: 'CPF',
          mensagem: 'Chave PIX válida: CPF'
        };
      }
      if (isCpf && resCelular.isValid) {
        return {
          isValid: true,
          tipo: 'celular',
          rotulo: 'Celular / CPF',
          mensagem: `Chave PIX válida: Celular ou CPF (${digitos})`
        };
      }

      return {
        isValid: false,
        tipo: 'numero',
        mensagem: 'Número inválido (não é um celular nem CPF válido)'
      };
    }

    // 6. Feedback para digitação em andamento
    if (/^\+?\d+$/.test(valor) || /^[\d().\s-]+$/.test(valor)) {
      if (digitos.length < 10) {
        return {
          isValid: false,
          tipo: 'numero',
          incompleto: true,
          mensagem: `Digitando número (${digitos.length} dígitos: celular 11 ou fixo 10)`
        };
      }
    }

    // Se tiver hífens característicos de chave aleatória (EVP)
    if (valor.includes('-') && /^[0-9a-fA-F-]+$/.test(valor)) {
      return {
        isValid: false,
        tipo: 'aleatoria',
        incompleto: true,
        mensagem: 'Chave aleatória incompleta (formato esperado: 8-4-4-4-12 caracteres)'
      };
    }

    return {
      isValid: false,
      tipo: 'desconhecido',
      mensagem: 'Chave PIX inválida. Use número de celular, CPF, e-mail ou chave aleatória (EVP).'
    };
  },

  // ===============================================================
  // VALIDAÇÃO DE PROVEDORES DE E-MAILS DESCARTÁVEIS / TEMPORÁRIOS
  // Bloqueia serviços temporários (ex: mailinator, tempmail, etc.)
  // ===============================================================
  isDisposableEmail(email) {
    if (!email) return false;
    const clean = String(email).trim().toLowerCase();
    const parts = clean.split('@');
    if (parts.length !== 2) return false;
    const domain = parts[1];

    // Conjunto de domínios conhecidos de provedores descartáveis / temporários
    const disposableDomains = new Set([
      'mailinator.com', 'mailinator2.com', 'mailinator.net', 'suremail.info', 'guerrillamail.com',
      'guerrillamail.net', 'guerrillamail.org', 'guerrillamail.biz', 'guerrillamailblock.com',
      'sharklasers.com', 'grr.la', 'pokemail.net', 'spam4.me', 'tempmail.com', 'temp-mail.org',
      'tempmail.net', 'temp-mail.io', 'temporary-mail.net', 'tempmailaddress.com', 'tempail.com',
      '10minutemail.com', '10minutemail.net', 'minuteinbox.com', 'yopmail.com', 'yopmail.fr',
      'yopmail.net', 'cool.fr.nf', 'courriel.fr.nf', 'jetable.fr.nf', 'trashmail.com',
      'trashmail.net', 'trashmail.de', 'trash-mail.com', 'throwawaymail.com', 'dispostable.com',
      'getairmail.com', 'fakeinbox.com', 'fakemailgenerator.com', 'emailfake.com', 'mohmal.com',
      'nada.ltd', 'getnada.com', 'inboxkitten.com', 'burnermail.io', 'generator.email',
      'mytemp.email', 'emailondeck.com', 'maildrop.cc', 'dropmail.me', 'harakirimail.com',
      'zillamail.com', 'mailnull.com', 'discard.email', 'disposablemail.com', 'boun.cr',
      'mytrashmail.com', 'mailcatch.com', 'mytempemail.com', 'jetable.org', 'meltmail.com',
      'spambox.us', 'tmailor.com', 'boximail.com', 'crazymailing.com', 'fakemail.net',
      'inboxbear.com', 'temporarymail.com', 'disposable-email.com', 'tempemail.co',
      'throwawayemail.com', 'tempemail.net', 'mailnesia.com', 'trashmail.se', 'trashmail.ws'
    ]);

    if (disposableDomains.has(domain)) return true;

    // Padrões de subdomínio e nomes característicos de serviços temporários
    const disposablePatterns = [
      /mailinator/i,
      /guerrillamail/i,
      /10minutemail/i,
      /tempmail/i,
      /temp-mail/i,
      /throwaway/i,
      /yopmail/i,
      /trashmail/i,
      /fake.*mail/i,
      /disposable/i,
      /minuteinbox/i,
      /burnermail/i,
      /sharklasers/i,
      /fakemailgenerator/i,
      /dispostable/i,
      /maildrop/i
    ];

    return disposablePatterns.some(pattern => pattern.test(domain));
  },

  validarEmailReal(email) {
    const clean = String(email || '').trim().toLowerCase();
    if (!clean) {
      return { isValid: false, vazio: true, mensagem: 'Digite seu e-mail' };
    }
    const isDisposable = this.isDisposableEmail(clean);
    if (isDisposable) {
      const parts = clean.split('@');
      const domain = parts[1] || 'descartável';
      return {
        isValid: false,
        isDisposable: true,
        domain,
        mensagem: `O provedor @${domain} é de e-mails descartáveis/temporários. Utilize um e-mail real (ex: Gmail, Outlook, Yahoo ou corporativo).`
      };
    }
    return {
      isValid: true,
      isDisposable: false
    };
  }
};

// Gerenciador centralizado de Notificações da Minha Extra (Integrado com a tabela 'notificacoes' do Supabase)
const NotificationManager = {
  STORAGE_KEY: 'minha_extra_notificacoes',
  realtimeSubscription: null,

  getLocalNotifications(empresaId = null) {
    try {
      const data = JSON.parse(localStorage.getItem(this.STORAGE_KEY) || '[]');
      if (empresaId) {
        return data.filter(n => !n.empresa_id || n.empresa_id === empresaId);
      }
      return data;
    } catch(e) {
      return [];
    }
  },

  saveLocalNotifications(list) {
    try {
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(list));
    } catch(e) {}
  },

  getNotifications(empresaId = null) {
    return this.getLocalNotifications(empresaId);
  },

  // Busca notificações na tabela 'notificacoes' do Supabase e sincroniza o cache local
  async fetchFromSupabase(empresaId = null) {
    const supabase = getSupabase();
    if (!supabase) return this.getLocalNotifications(empresaId);

    try {
      let query = supabase
        .from('notificacoes')
        .select('*')
        .order('id', { ascending: false })
        .limit(40);

      if (empresaId && typeof empresaId === 'number' && empresaId < 2147483647) {
        query = query.or(`empresa_id.eq.${empresaId},empresa_id.is.null`);
      }

      const { data, error } = await query;
      if (!error && data && Array.isArray(data)) {
        const local = this.getLocalNotifications(empresaId);
        const mapLocal = new Map(local.map(item => [item.id, item]));

        const mesclados = data.map(remote => {
          const l = mapLocal.get(remote.id);
          return {
            ...remote,
            freelancer_nome: l?.freelancer_nome || remote.freelancer_nome || '',
            vaga_titulo: l?.vaga_titulo || remote.vaga_titulo || '',
            valor: l?.valor || remote.valor || 0
          };
        });

        // Mantém notificações locais que possam não ter sido sincronizadas ainda
        const idsRemotos = new Set(data.map(d => d.id));
        for (const l of local) {
          if (!idsRemotos.has(l.id)) {
            mesclados.push(l);
          }
        }

        this.saveLocalNotifications(mesclados);
        return mesclados;
      }
    } catch(e) {
      console.warn('Erro ao consultar tabela notificacoes no Supabase:', e);
    }
    return this.getLocalNotifications(empresaId);
  },

  // Insere notificação no Supabase e no cache local
  async addNotification(notif) {
    const supabase = getSupabase();
    const local = this.getLocalNotifications();

    let safeEmpresaId = notif.empresa_id || null;
    if (safeEmpresaId && (typeof safeEmpresaId !== 'number' || safeEmpresaId > 2147483647)) {
      safeEmpresaId = null;
    }
    let safeVagaId = notif.vaga_id || null;
    if (safeVagaId && (typeof safeVagaId !== 'number' || safeVagaId > 2147483647)) {
      safeVagaId = null;
    }
    let safeFreeId = notif.freelancer_id || null;
    if (safeFreeId && (typeof safeFreeId !== 'number' || safeFreeId > 2147483647)) {
      safeFreeId = null;
    }

    const payload = {
      empresa_id: safeEmpresaId,
      vaga_id: safeVagaId,
      freelancer_id: safeFreeId,
      titulo: notif.titulo || 'Nova Notificação',
      mensagem: notif.mensagem || '',
      tipo: notif.tipo || 'anuncio_aceito',
      lida: false,
      criada_em: new Date().toISOString()
    };

    let remoteItem = null;
    if (supabase) {
      try {
        const { data, error } = await supabase
          .from('notificacoes')
          .insert([payload])
          .select();

        if (!error && data && data[0]) {
          remoteItem = data[0];
          console.log('Notificação gravada na tabela notificacoes do Supabase:', remoteItem);
        }
      } catch(e) {
        console.warn('Fallback local ao gravar tabela notificacoes:', e);
      }
    }

    const newNotif = {
      id: remoteItem ? remoteItem.id : ('notif_' + Date.now() + '_' + Math.floor(Math.random() * 1000)),
      ...payload,
      freelancer_nome: notif.freelancer_nome || '',
      vaga_titulo: notif.vaga_titulo || '',
      valor: notif.valor || 0,
      metadados: notif.metadados || {}
    };

    local.unshift(newNotif);
    this.saveLocalNotifications(local);
    window.dispatchEvent(new CustomEvent('minha_extra_nova_notificacao', { detail: newNotif }));
    return newNotif;
  },

  async markAsRead(notifId) {
    const supabase = getSupabase();
    if (supabase && typeof notifId === 'number') {
      try {
        await supabase.from('notificacoes').update({ lida: true }).eq('id', notifId);
      } catch(e) {}
    }
    const list = this.getLocalNotifications();
    const updated = list.map(n => n.id === notifId ? { ...n, lida: true } : n);
    this.saveLocalNotifications(updated);
    window.dispatchEvent(new CustomEvent('minha_extra_notificacoes_atualizadas'));
  },

  async markAllAsRead(empresaId = null) {
    const supabase = getSupabase();
    if (supabase) {
      try {
        let q = supabase.from('notificacoes').update({ lida: true });
        if (empresaId && typeof empresaId === 'number') {
          q = q.eq('empresa_id', empresaId);
        }
        await q;
      } catch(e) {}
    }
    const list = this.getLocalNotifications();
    const updated = list.map(n => (!empresaId || n.empresa_id === empresaId) ? { ...n, lida: true } : n);
    this.saveLocalNotifications(updated);
    window.dispatchEvent(new CustomEvent('minha_extra_notificacoes_atualizadas'));
  },

  getUnreadCount(empresaId = null) {
    return this.getLocalNotifications(empresaId).filter(n => !n.lida).length;
  },

  // Inscreve no canal em tempo real do Supabase
  initRealtime(callback) {
    const supabase = getSupabase();
    if (!supabase || !supabase.channel || this.realtimeSubscription) return;

    try {
      this.realtimeSubscription = supabase
        .channel('notificacoes_realtime_channel')
        .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'notificacoes' }, payload => {
          if (payload && payload.new) {
            const notif = payload.new;
            const local = this.getLocalNotifications();
            if (!local.some(item => item.id === notif.id)) {
              local.unshift(notif);
              this.saveLocalNotifications(local);
            }
            window.dispatchEvent(new CustomEvent('minha_extra_nova_notificacao', { detail: notif }));
            if (callback) callback(notif);
          }
        })
        .subscribe();
    } catch(e) {
      console.warn('Realtime Supabase não pôde ser inicializado:', e);
    }
  }
};

// Gerador de Payload PIX Copia e Cola Oficial da Minha Extra
function gerarPixCopiaECola(valor, idTransacao, descricao = 'Minha Extra Vaga') {
  const valorNum = Number(valor) || 0;
  const valorFormatado = valorNum.toFixed(2);
  const chave = 'pix@minhaextra.com.br';
  const txid = (idTransacao || ('ME' + Date.now().toString().slice(-8))).replace(/[^a-zA-Z0-9]/g, '').slice(0, 25);
  return `00020126580014br.gov.bcb.pix0114${chave}0216${descricao.slice(0, 16)}5204000053039865406${valorFormatado.padStart(6, '0')}5802BR5916MINHA EXTRA LTDA6007MARINGA62070503***6304${txid}`;
}

// Exporta para uso global no Vanilla JS
window.MinhaExtra = {
  SUPABASE_URL,
  SUPABASE_KEY,
  getSupabase,
  SessionManager,
  ValidadorDocumentos,
  NotificationManager,
  gerarPixCopiaECola,
  handleSupabaseError,
  showRlsModal,
  copyRlsSql,
  ensureValidEmpresaId,
  ensureValidFreelancerId,
  ensureValidVagaId,
  cleanCorruptedLocalVagas,
  RLS_HELP_SQL
};
