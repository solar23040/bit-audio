package com.solar23040.bitaudio.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Forum
import androidx.compose.material.icons.filled.NearMe
import androidx.compose.material.icons.outlined.Forum
import androidx.compose.material.icons.outlined.NearMe
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable

enum class HomeTab { NEARBY, CHANNELS }

/** Two top-level destinations: the public nearby feed and private channels. */
@Composable
fun AppBottomBar(
    selected: HomeTab,
    onSelect: (HomeTab) -> Unit,
) {
    NavigationBar {
        NavigationBarItem(
            selected = selected == HomeTab.NEARBY,
            onClick = { onSelect(HomeTab.NEARBY) },
            icon = {
                Icon(
                    imageVector = if (selected == HomeTab.NEARBY) {
                        Icons.Filled.NearMe
                    } else {
                        Icons.Outlined.NearMe
                    },
                    contentDescription = null,
                )
            },
            label = { Text("Nearby") },
        )
        NavigationBarItem(
            selected = selected == HomeTab.CHANNELS,
            onClick = { onSelect(HomeTab.CHANNELS) },
            icon = {
                Icon(
                    imageVector = if (selected == HomeTab.CHANNELS) {
                        Icons.Filled.Forum
                    } else {
                        Icons.Outlined.Forum
                    },
                    contentDescription = null,
                )
            },
            label = { Text("Channels") },
        )
    }
}
