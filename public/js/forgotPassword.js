
import '@babel/polyfill'
import axios from 'axios';
import {showAlert} from './alerts';


export const forgotPassword = async (email) => {
  try{
    const res = await axios({
      method: 'POST',
      url: 'api/v1/users/forgotPassword',
      data: {
        email,
      },
    });

    if(res.data.status === 'success'){
      showAlert('success','reset password link sent to email!');
      window.setTimeout(() => {
        location.assign('/changePassword')
      }, 1500)
    }
  }catch (err) {
    showAlert('error', err.response.data.message);
  }
}
