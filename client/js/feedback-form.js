/**
 * Shared Feedback Form Component
 * Provides star rating and form submission functionality
 */

function escapeHtmlAttr(str) {
    if (str == null) return '';
    const s = String(str);
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

class FeedbackForm {
    constructor(containerId, options = {}) {
        this.container = document.getElementById(containerId);
        this.options = {
            eventName: options.eventName || null,
            token: options.token || null, // Security token for external submissions
            showEventInput: options.showEventInput !== false,
            preserveEventName: options.preserveEventName !== false, // Keep event name after submit
            onSuccess: options.onSuccess || this.defaultSuccessHandler,
            onError: options.onError || this.defaultErrorHandler
        };
        this.rating = 0;
        this.state = 'ready'; // 'ready', 'submitting', 'success'
        this.init();
    }

    init() {
        this.render();
        this.attachEventListeners();
    }

    render() {
        this.container.innerHTML = `
            <form id="feedback-form" class="feedback-form">
                ${this.options.showEventInput ? `
                    <div class="form-group">
                        <label for="event-name">Event Name</label>
                        <input type="text" id="event-name" name="event_name" 
                               value="${escapeHtmlAttr(this.options.eventName || '')}" 
                               ${this.options.eventName ? 'readonly' : ''} 
                               required>
                    </div>
                ` : `
                    <input type="hidden" id="event-name" name="event_name" value="${escapeHtmlAttr(this.options.eventName || '')}">
                `}
                
                <div class="form-group">
                    <label>Rating</label>
                    <div class="star-rating" id="star-rating">
                        ${[1, 2, 3, 4, 5].map(num => `
                            <span class="star" data-rating="${num}" title="${num} star${num > 1 ? 's' : ''}">★</span>
                        `).join('')}
                    </div>
                    <input type="hidden" id="rating-value" name="rating" value="" required>
                </div>
                
                <div class="form-group">
                    <label for="comment">Comment (optional)</label>
                    <textarea id="comment" name="comment" rows="4" 
                              placeholder="Tell us about your experience..."></textarea>
                </div>
                
                <button type="submit" class="submit-btn" id="submit-btn">
                    <span class="btn-spinner"></span>
                    <span class="btn-text">Submit Feedback</span>
                </button>
            </form>
            
            <div id="form-message" class="form-message"></div>
        `;
    }

    attachEventListeners() {
        // Star rating click handlers
        const stars = this.container.querySelectorAll('.star');
        stars.forEach(star => {
            star.addEventListener('click', (e) => this.setRating(parseInt(e.target.dataset.rating)));
            star.addEventListener('mouseenter', (e) => this.highlightStars(parseInt(e.target.dataset.rating)));
            star.addEventListener('mouseleave', () => this.highlightStars(this.rating));
        });

        // Form submission
        const form = this.container.querySelector('#feedback-form');
        form.addEventListener('submit', (e) => this.handleSubmit(e));
    }

    setRating(rating) {
        this.rating = rating;
        this.container.querySelector('#rating-value').value = rating;
        this.highlightStars(rating);
    }

    highlightStars(rating) {
        const stars = this.container.querySelectorAll('.star');
        stars.forEach((star, index) => {
            if (index < rating) {
                star.classList.add('active');
            } else {
                star.classList.remove('active');
            }
        });
    }

    async handleSubmit(e) {
        e.preventDefault();
        
        const submitBtn = this.container.querySelector('#submit-btn');
        
        // If in success state, "Add Another" was clicked - reset for new entry
        if (this.state === 'success') {
            this.resetForm();
            this.setButtonState('ready');
            this.hideMessage();
            return;
        }
        
        const eventName = this.container.querySelector('#event-name').value.trim();
        const rating = this.rating;
        const comment = this.container.querySelector('#comment').value.trim();

        if (!eventName) {
            this.showMessage('Please enter an event name.', 'error');
            return;
        }

        if (!rating) {
            this.showMessage('Please select a rating.', 'error');
            return;
        }

        this.setButtonState('submitting');

        try {
            const response = await fetch('/api/feedback', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    event_name: eventName,
                    rating: rating,
                    comment: comment || null,
                    ...(this.options.token && { token: this.options.token })
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.options.onSuccess.call(this, data);
                this.resetForm();
                this.setButtonState('success');
            } else {
                this.options.onError.call(this, data.error || 'Failed to submit feedback');
                this.setButtonState('ready');
            }
        } catch (error) {
            this.options.onError.call(this, 'Network error. Please try again.');
            this.setButtonState('ready');
        }
    }

    setButtonState(state) {
        this.state = state;
        const submitBtn = this.container.querySelector('#submit-btn');
        const btnText = submitBtn.querySelector('.btn-text');
        
        submitBtn.classList.remove('submitting', 'success');
        
        switch (state) {
            case 'submitting':
                submitBtn.disabled = true;
                submitBtn.classList.add('submitting');
                btnText.textContent = 'Submitting...';
                break;
            case 'success':
                submitBtn.disabled = false;
                submitBtn.classList.add('success');
                btnText.textContent = 'Add Another';
                break;
            case 'ready':
            default:
                submitBtn.disabled = false;
                btnText.textContent = 'Submit Feedback';
                break;
        }
    }

    hideMessage() {
        const messageEl = this.container.querySelector('#form-message');
        messageEl.style.display = 'none';
    }

    resetForm() {
        // Reset rating
        this.rating = 0;
        this.highlightStars(0);
        this.container.querySelector('#rating-value').value = '';
        
        // Reset comment
        this.container.querySelector('#comment').value = '';
        
        // Only reset event name if preserveEventName is false
        if (!this.options.preserveEventName && this.options.showEventInput && !this.options.eventName) {
            this.container.querySelector('#event-name').value = '';
        }
    }

    showMessage(message, type = 'success') {
        const messageEl = this.container.querySelector('#form-message');
        messageEl.textContent = message;
        messageEl.className = `form-message ${type}`;
        messageEl.style.display = 'block';
        
        if (type === 'success') {
            setTimeout(() => {
                messageEl.style.display = 'none';
            }, 5000);
        }
    }

    defaultSuccessHandler(data) {
        this.showMessage('Thank you for your feedback!', 'success');
    }

    defaultErrorHandler(error) {
        this.showMessage(error, 'error');
    }
}

// Export for use in different contexts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FeedbackForm;
}
