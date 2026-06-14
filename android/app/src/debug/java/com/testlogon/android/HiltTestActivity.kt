package com.testlogon.android

import androidx.activity.ComponentActivity
import dagger.hilt.android.AndroidEntryPoint

/** Empty @AndroidEntryPoint activity so createAndroidComposeRule can host hiltViewModel()-using content. */
@AndroidEntryPoint
class HiltTestActivity : ComponentActivity()
