package com.solar23040.bitaudio.ui.screens

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.solar23040.bitaudio.AppGraph
import com.solar23040.bitaudio.ui.components.AppBottomBar
import com.solar23040.bitaudio.ui.components.HomeTab

/** Owns the two top-level tabs so switching them does not rebuild the mesh state. */
@Composable
fun HomeScreen(
    graph: AppGraph,
    onOpenChannel: (String) -> Unit,
    onJoinChannel: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(HomeTab.NEARBY) }
    val bottomBar: @Composable () -> Unit = {
        AppBottomBar(selected = tab, onSelect = { tab = it })
    }

    when (tab) {
        HomeTab.NEARBY -> NearbyScreen(
            graph = graph,
            onOpenSettings = onOpenSettings,
            bottomBar = bottomBar,
        )
        HomeTab.CHANNELS -> ChannelListScreen(
            graph = graph,
            onOpenChannel = onOpenChannel,
            onJoinChannel = onJoinChannel,
            onOpenSettings = onOpenSettings,
            bottomBar = bottomBar,
        )
    }
}
