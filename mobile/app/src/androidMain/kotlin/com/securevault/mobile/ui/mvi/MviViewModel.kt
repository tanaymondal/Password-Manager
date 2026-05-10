package com.securevault.mobile.ui.mvi

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

abstract class MviViewModel<I : MviIntent, S : MviState, E : MviEffect>(
    initialState: S
) : ViewModel() {
    private val viewModelScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _state = MutableStateFlow(initialState)
    val state: StateFlow<S> = _state.asStateFlow()

    private val _effect = MutableSharedFlow<E>()
    val effect: SharedFlow<E> = _effect.asSharedFlow()

    protected val currentState: S
        get() = _state.value

    abstract fun handleIntent(intent: I)

    protected fun setState(reduce: S.() -> S) {
        _state.update { it.reduce() }
    }

    protected fun setEffect(effect: E) {
        viewModelScope.launch {
            _effect.emit(effect)
        }
    }

    protected fun launch(block: suspend () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            block()
        }
    }

    protected fun <T> runInBackground(block: suspend () -> T, onResult: (Result<T>) -> Unit) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { block() }
            }
            onResult(result)
        }
    }
}