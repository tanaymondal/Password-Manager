package com.securevault.mobile.ui.mvi

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import com.securevault.mobile.ui.mvi.ioDispatcher
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

abstract class MviViewModel<I : MviIntent, S : MviState, E : MviEffect>(
    initialState: S
) {
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
        viewModelScope.launch(ioDispatcher) {
            block()
        }
    }

    protected fun <T> runInBackground(block: suspend () -> T, onResult: (Result<T>) -> Unit) {
        viewModelScope.launch {
            val result = withContext(ioDispatcher) {
                runCatching { block() }.fold(
                    onSuccess = { Result.success(it) },
                    onFailure = { Result.failure(it) }
                )
            }
            onResult(result)
        }
    }
}
