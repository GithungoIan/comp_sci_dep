import '@babel/polyfill'
import axios from 'axios';
import {showAlert} from './alerts';


export const resetPassword = async(password, passwordConfirm) => {
  try{
    const res = await axios({
      method: 'PATCH',
      url : '/api/v1/users/resetPassword/:token',
      data: {
        password,
        passwordConfirm,
      }
    });
    if(res.data.status === 'success') {
      showAlert('success', 'password reset successful!');
      window.setTimeout(() => {
        location.assign('/login');
      }, 1000);
    }
  }catch (err) {
    showAlert('Error', err.response.data.message);
  }
}
