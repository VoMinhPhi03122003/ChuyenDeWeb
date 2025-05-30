import PropTypes from "prop-types";
import React, {Fragment, useEffect, useState} from "react";
import {Link} from "react-router-dom";
import Tab from "react-bootstrap/Tab";
import Nav from "react-bootstrap/Nav";
import Breadcrumb from "../../wrappers/breadcrumb/Breadcrumb";
import useForm from "../../components/auth/FormLogin";
import {Navigate} from 'react-router-dom';
import {FiCommand} from "react-icons/fi";
import {GoogleLogin} from "@react-oauth/google";
import axios from "axios";

const LoginRegister = () => {
        const [user, setUser] = useState(false);
        const [loading, setLoading] = useState(false);

        const {handleSubmit, status} = useForm(setLoading);

        const loginGoogleHandle = async (credentialResponse: any) => {
            console.log(credentialResponse)
            await axios.post(process.env.REACT_APP_API_ENDPOINT + "auth/google",
                {token: credentialResponse.credential}
                , {
                    headers: {
                        Accept: 'application/json',
                        'Content-Type': 'application/json'
                    }
                }).then((response) => {
                if (response.status === 200) {
                    localStorage.setItem('user', JSON.stringify(response.data));
                    window.location.href = '/';
                }
                setLoading(false);
            }).catch((error) => {
                console.error('There was an error!', error);
                setLoading(false);
            });

        }

        useEffect(() => {
            const checkUser = () => {
                if (localStorage.getItem("user") !== null && localStorage.getItem("user") !== "") {
                    setUser(true);
                }
            };
            checkUser();
        }, []);

        if (user) return (<Navigate to="/"/>)

        return (
            <Fragment>
                <Breadcrumb/>
                <div className="login-register-area pt-100 pb-100">
                    <div className="container">
                        <div className="row">
                            <div className="col-lg-7 col-md-12 ml-auto m-auto">
                                <div className="login-register-wrapper">
                                    <Tab.Container defaultActiveKey="login">
                                        <Nav variant="pills" className="login-register-tab-list">
                                            <Nav.Item>
                                                <Nav.Link eventKey="login">
                                                    <h4>Đăng nhập</h4>
                                                </Nav.Link>
                                            </Nav.Item>
                                            <Nav.Item>
                                                <Nav.Link eventKey="register">
                                                    <h4>Đăng ký</h4>
                                                </Nav.Link>
                                            </Nav.Item>
                                        </Nav>
                                        <Tab.Content>
                                            <Tab.Pane eventKey="login">
                                                <div className="login-form-container">
                                                    <div className="login-register-form">
                                                        {status === 404 ?
                                                            <p className={"text-danger align-text-bottom center"}
                                                               style={{textAlign: "center", fontSize: 20}}>Không
                                                                tìm thấy tên đăng
                                                                nhập</p> : status === 417 ?
                                                                <p className={"text-danger align-text-bottom center"}
                                                                   style={{textAlign: "center", fontSize: 20}}>Sai
                                                                    mật khẩu</p> : <></>}
                                                        <form onSubmit={handleSubmit}
                                                              action={process.env.REACT_APP_API_ENDPOINT + "auth/login"}
                                                              method="POST">
                                                            <input
                                                                type="text"
                                                                name="username"
                                                                placeholder="Tên đăng nhập"
                                                            />
                                                            <input
                                                                type="password"
                                                                name="password"
                                                                placeholder="Mật khẩu"
                                                            />
                                                            <div className="button-box">
                                                                <div className="login-toggle-btn">
                                                                    <input type="checkbox"/>
                                                                    <label className="ml-10">Nhớ tài khoản</label>
                                                                    <Link to={"/forgot-password"}>
                                                                        Quên mật khẩu?
                                                                    </Link>
                                                                </div>
                                                                {loading ? <button disabled={true}>
                                                                        <span><FiCommand className="loading-icon"/></span>
                                                                    </button> :
                                                                    <div style={{
                                                                        display: "flex",
                                                                        justifyContent: "space-between",
                                                                        alignItems: "center",
                                                                        flexDirection: "row",

                                                                    }}>
                                                                        <button type="submit"
                                                                                style={{float: "left", height: "50px"}}>
                                                                            <span>Đăng nhập</span>
                                                                        </button>

                                                                        <p style={{
                                                                            textAlign: "center",
                                                                            marginBottom: "0px"
                                                                        }}>Hoặc</p>

                                                                        <GoogleLogin
                                                                            onSuccess={loginGoogleHandle}
                                                                            onError={() => {
                                                                                console.error("Error");
                                                                            }}
                                                                        />
                                                                    </div>
                                                                }
                                                            </div>
                                                        </form>
                                                    </div>
                                                </div>
                                            </Tab.Pane>
                                            <Tab.Pane eventKey="register">
                                                <div className="login-form-container">
                                                    <div className="login-register-form">
                                                        <form>
                                                            <input
                                                                type="text"
                                                                name="user-name"
                                                                placeholder="Tên đăng nhập"
                                                            />
                                                            <input
                                                                type="password"
                                                                name="user-password"
                                                                placeholder="Mật khẩu"
                                                            />
                                                            <input
                                                                name="user-email"
                                                                placeholder="Email"
                                                                type="email"
                                                            />
                                                            <div className="button-box">
                                                                <button type="submit">
                                                                    <span>Đăng ký</span>
                                                                </button>
                                                            </div>
                                                        </form>
                                                    </div>
                                                </div>
                                            </Tab.Pane>
                                        </Tab.Content>
                                    </Tab.Container>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </Fragment>
        );
    }
;

LoginRegister.propTypes = {
    location: PropTypes.object
};

export default LoginRegister;
