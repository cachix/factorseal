package com.cachix.factorseal.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.cachix.factorseal.app.FactorSeal
import com.cachix.factorseal.app.Phase
import com.cachix.factorseal.app.icon
import com.cachix.factorseal.core.ErrorCode
import com.cachix.factorseal.core.Kind
import com.cachix.factorseal.core.Login
import com.cachix.factorseal.core.LoginChange
import com.cachix.factorseal.core.Request
import com.cachix.factorseal.core.Response
import com.cachix.factorseal.core.Site
import com.cachix.factorseal.core.VaultException
import com.cachix.factorseal.resources.Res
import com.cachix.factorseal.resources.cancel
import com.cachix.factorseal.resources.close
import com.cachix.factorseal.resources.fill
import com.cachix.factorseal.resources.fill_a_login
import com.cachix.factorseal.resources.fill_in_app
import com.cachix.factorseal.resources.fill_in_app_line
import com.cachix.factorseal.resources.login_already_saved
import com.cachix.factorseal.resources.login_saved
import com.cachix.factorseal.resources.no_logins_for_app
import com.cachix.factorseal.resources.no_logins_for_website
import com.cachix.factorseal.resources.no_logins_to_fill
import com.cachix.factorseal.resources.other_logins
import com.cachix.factorseal.resources.saving_login
import com.cachix.factorseal.ui.components.Banner
import com.cachix.factorseal.ui.components.Button
import com.cachix.factorseal.ui.components.ButtonSize
import com.cachix.factorseal.ui.components.Dialog
import com.cachix.factorseal.ui.components.Divider
import com.cachix.factorseal.ui.components.EmptyState
import com.cachix.factorseal.ui.components.IconTile
import com.cachix.factorseal.ui.components.Layers
import com.cachix.factorseal.ui.components.ListHeader
import com.cachix.factorseal.ui.components.ListRow
import com.cachix.factorseal.ui.components.Mark
import com.cachix.factorseal.ui.components.Pill
import com.cachix.factorseal.ui.components.RowText
import com.cachix.factorseal.ui.components.Spinner
import com.cachix.factorseal.ui.components.Text
import com.cachix.factorseal.ui.components.Variant
import com.cachix.factorseal.ui.components.VaultCard
import com.cachix.factorseal.ui.components.afterAMoment
import com.cachix.factorseal.ui.theme.Semibold
import com.cachix.factorseal.ui.theme.Theme
import com.cachix.factorseal.ui.theme.Type
import org.jetbrains.compose.resources.getString
import org.jetbrains.compose.resources.stringResource

class AutofillTask<T : Any> {
    var result by mutableStateOf<T?>(null)
        private set
    var problem by mutableStateOf<String?>(null)
        private set
    var busy by mutableStateOf(false)
        private set

    fun run(
        app: FactorSeal,
        action: suspend () -> T,
    ) {
        if (busy || result != null) return
        busy = true
        problem = null
        app.run {
            try {
                result = action()
            } catch (failure: VaultException) {
                if (failure.code != ErrorCode.Sealed) problem = failure.message
            }
            busy = false
        }
    }
}

@Composable
fun AutofillScreen(
    app: FactorSeal,
    task: AutofillTask<Response.Credentials>,
    site: Site,
    label: String,
    onFill: (Response.Credentials) -> Unit,
    onClose: () -> Unit,
) {
    AutofillFrame(app, onClose) { LoginPicker(app, task, site, label, onFill, onClose) }
}

@Composable
fun AutofillSaveScreen(
    app: FactorSeal,
    task: AutofillTask<String>,
    site: Site,
    label: String,
    username: String,
    password: String,
    onDone: (String?) -> Unit,
) {
    AutofillFrame(app, onClose = { onDone(null) }) { Saving(app, task, Request.SaveLogin(site, label, username, password), label, onDone) }
}

@Composable
private fun AutofillFrame(
    app: FactorSeal,
    onClose: () -> Unit,
    unsealed: @Composable () -> Unit,
) {
    AppFrame(app, remember { Layers() }) {
        when (val phase = app.phase) {
            Phase.Setup -> LaunchedEffect(Unit) { onClose() }
            is Phase.Sealed -> SealedScreen(app, settings = false)
            is Phase.Unavailable -> UnavailableScreen(app, phase.failure, settings = false)
            Phase.Unsealed -> unsealed()
            Phase.Starting, Phase.Creating, Phase.Sealing -> Starting()
        }
    }
}

@Composable
private fun LoginPicker(
    app: FactorSeal,
    task: AutofillTask<Response.Credentials>,
    site: Site,
    label: String,
    onFill: (Response.Credentials) -> Unit,
    onClose: () -> Unit,
) {
    var logins by remember { mutableStateOf<Response.Logins?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }
    var confirming by remember { mutableStateOf<Login?>(null) }
    val query = remember { TextFieldState() }
    LaunchedEffect(site) {
        try {
            logins = app.call<Response.Logins>(Request.Logins(site))
        } catch (failure: VaultException) {
            if (failure.code != ErrorCode.Sealed) problem = failure.message
        }
    }
    fun fill(
        login: Login,
        learns: Boolean,
    ) {
        task.run(app) {
            val credentials = app.call<Response.Credentials>(Request.Fill(login.id, site))
            if (learns) app.changed()
            credentials
        }
    }
    task.result?.let { credentials -> LaunchedEffect(credentials) { onFill(credentials) } }
    val search = query.text.toString().trim().lowercase()
    val others =
        logins?.others.orEmpty().filter { login ->
            login.title.lowercase().contains(search) || login.username.lowercase().contains(search)
        }
    MainPage {
        BackRow(app, onBack = onClose)
        ListHeader(stringResource(Res.string.fill_a_login)) { Pill(label, Modifier.widthIn(max = 200.dp)) }
        (task.problem ?: problem)?.let { Banner(it, Modifier.padding(16.dp)) }
        val loaded = logins
        when {
            loaded == null && problem == null ->
                Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                    Spinner(Modifier.afterAMoment(), size = 24.dp, color = Theme.colors.mutedForeground)
                }

            loaded == null -> Unit

            loaded.linked.isEmpty() && loaded.others.isEmpty() ->
                EmptyState(
                    stringResource(Res.string.no_logins_to_fill),
                    stringResource(if (site.web != null) Res.string.no_logins_for_website else Res.string.no_logins_for_app),
                )

            else ->
                LazyColumn(Modifier.fillMaxSize()) {
                    items(loaded.linked, key = { it.id }) { login -> LoginRow(login, onClick = { fill(login, learns = false) }) }
                    if (loaded.others.isNotEmpty()) {
                        item(key = "others") { OthersHeader(query) }
                        items(others, key = { "other-${it.id}" }) { login -> LoginRow(login, onClick = { confirming = login }) }
                    }
                }
        }
    }
    confirming?.let { login ->
        Dialog(
            title = stringResource(Res.string.fill_in_app, login.title, label),
            onDismiss = { confirming = null },
            actions = {
                Button(stringResource(Res.string.cancel), onClick = { confirming = null })
                Button(
                    stringResource(Res.string.fill),
                    onClick = {
                        confirming = null
                        fill(login, learns = true)
                    },
                    variant = Variant.Primary,
                )
            },
        ) {
            Text(stringResource(Res.string.fill_in_app_line), color = Theme.colors.mutedForeground)
        }
    }
}

@Composable
private fun LoginRow(
    login: Login,
    onClick: () -> Unit,
) {
    ListRow(onClick) {
        IconTile(Kind.Login.icon())
        RowText(login.title, login.username.ifEmpty { null })
    }
}

@Composable
private fun OthersHeader(query: TextFieldState) {
    Column(Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(start = 16.dp, end = 16.dp, top = 20.dp, bottom = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(stringResource(Res.string.other_logins), style = Type.caption, color = Theme.colors.mutedForeground, weight = Semibold)
            SearchInput(query)
        }
        Divider()
    }
}

@Composable
private fun Saving(
    app: FactorSeal,
    task: AutofillTask<String>,
    request: Request.SaveLogin,
    label: String,
    onDone: (String?) -> Unit,
) {
    LaunchedEffect(task) {
        if (task.problem == null) {
            task.run(app) {
                val saved = app.call<Response.LoginSaved>(request)
                if (saved.change != LoginChange.Unchanged) app.changed()
                getString(if (saved.change == LoginChange.Unchanged) Res.string.login_already_saved else Res.string.login_saved, label)
            }
        }
    }
    task.result?.let { message -> LaunchedEffect(message) { onDone(message) } }
    Framed(app, settings = false) {
        VaultCard {
            Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Mark(56.dp)
                val failed = task.problem
                if (failed == null) {
                    Spinner(size = 32.dp)
                    Text(stringResource(Res.string.saving_login), style = Type.title, align = TextAlign.Center)
                } else {
                    Banner(failed)
                    Button(stringResource(Res.string.close), onClick = { onDone(null) }, modifier = Modifier.fillMaxWidth(), size = ButtonSize.Large)
                }
            }
        }
    }
}
