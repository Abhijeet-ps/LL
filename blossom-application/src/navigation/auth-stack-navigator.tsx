import { createNativeStackNavigator } from '@react-navigation/native-stack'
import React from 'react'
import { AuthStackParamList } from './types'
import WelcomeScreen from '@/screens/welcome-screen'
import SignInScreen from '@/screens/sign-in-screen'
import SignUpScreen from '@/screens/sign-up-screen'

const Stack = createNativeStackNavigator<AuthStackParamList>()

const AuthStackNavigator = () => {
    return (
        <Stack.Navigator>
            <Stack.Screen name = 'Welcome' 
            options={{
               headerShown: false
            }}
            component={WelcomeScreen}/>

            <Stack.Screen name = 'SignIn' 
            options={{
                headerShown: false
            }}
            component={SignInScreen}/>

            <Stack.Screen name = 'SignUp' 
            options={{
                headerShown: false
            }}
            component={SignUpScreen}/>

        </Stack.Navigator>
    )
}

export default AuthStackNavigator